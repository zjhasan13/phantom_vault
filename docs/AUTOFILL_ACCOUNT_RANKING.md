# How Bitwarden picks the right account on a multi-step login

Sources: `github.com/bitwarden/clients` **@ main**, read 2026-11-04. Line numbers
are from that snapshot. Raw files:

- `apps/browser/src/autofill/background/overlay.background.ts`
- `libs/common/src/vault/services/cipher.service.ts`
- `apps/browser/src/autofill/services/autofill.service.ts`
- `libs/common/src/vault/utils/cipher-view-like-utils.ts`
- `apps/browser/src/autofill/content/components/inline-menu/cipher-details.ts`
- `apps/browser/src/autofill/overlay/inline-menu/pages/list/autofill-inline-menu-list.ts`

## Short answer

Bitwarden does **not** read the account the page is showing. It:

1. cuts the list down by **URL match**,
2. sorts by **per-item `lastUsedDate` desc**, ties by **name, then username**,
3. prints the **username as the second line of every row**,
4. lets a repeated fill shortcut **cycle** through the matches.

The account on Google's password chip never enters the decision. If the wrong
account is on top, the user was the last one to fill it.

## Evidence

**1. Candidate set is URL-only.** `overlay.background.ts:586-592` and
`:610-616` call `cipherService.getAllDecryptedForUrl(...)` then
`.sort(sortCiphersByLastUsedThenName)`. `cipher.service.ts:522-554` filters by
`CipherViewLikeUtils.matchesUri(...)` and nothing else — deleted, archived and
restricted items are the only other exclusions. The default match strategy is
`UriMatchStrategy.Domain` (`cipher-view-like-utils.ts:280-296`), so
`accounts.google.com` matches an item saved with `google.com`.

**2. Ordering is last-used, then name+username.** `cipher.service.ts:1235-1257`
returns a descending `localData.lastUsedDate` comparison; `:1259-1266` falls back
to the locale collator; `:1268-1305` compares the item name and then appends
`login.username` to the name before the final collator pass, so two identically
named Google items are ordered by their usernames.

**3. `lastUsedDate` is written only by an actual fill.**
`autofill.service.ts:545-547` calls `cipherService.updateLastUsedDate(...)` inside
the fill path (`options.skipLastUsed` guards the exceptions).
`cipher.service.ts:685-700` stores it in the client-only `localData` map.

**4. One URL, many matches → round-robin.** `cipher.service.ts:1628-1673`
memoises the sorted list per URL in `sortedCiphersCache` and returns
`getLastUsed` / `getLastLaunched` / `getNext`. So pressing the fill shortcut
again walks to the next account instead of always offering the same one.

**5. Rows disambiguate visually.** `getInlineMenuCipherData` puts
`username: cipher.login.username` on every row (`overlay.background.ts:912`);
`cipher-details.ts:23` and `:48-60` render it as the subtitle. The list shows six
ciphers per page and loads more on scroll (`autofill-inline-menu-list.ts:81`,
`:740-745`).

**6. No page-account read in that path.** The cipher-selection path we traced
receives only the tab URL (`getCipherViews(currentTab, …)`), plus a focused-field
boolean used for menu positioning (`overlay.background.ts:1441-1447`). Nothing
in it parses `data-identifier`, `identifierId`, or a chip. Caveat: this is the
traced path, not a whole-repo code search (GitHub code search needs auth and
Sourcegraph returned nothing useful), so treat "Bitwarden never reads the page
account" as *not found in this path* rather than proven absent everywhere.

## Why that is not enough on Google's password step

That page shows the account as a chip, not an `<input>`. There is no username
field to compare against, so the only remaining signal is *which Google item was
filled last*. Fill `wopijov565` five minutes ago and it sits above `zjhasan3`
until you fill `zjhasan3`. Bitwarden accepts that ambiguity and leans on the
username subtitle plus the cycling shortcut.

## What PhantomVault does differently

`browser_extension/content.js:1811-1819` ranks:

```
page/typed account  →  last_filled  →  verified  →  username A→Z
```

`verified` is a sticky "this password worked on this site" flag. It used to
outrank recency, so a stale-but-once-working account could beat the account that
was filled most recently — the `wopijov565` / `zjhasan3` report. The page-hint key
added in `61c785e` fixes the case where the page still displays the account;
`c2cc3de` moved recency above `verified` for the case where it does not.

## Options

| | Order | Effect |
|---|---|---|
| A (previous) | hint → verified → last_filled → name | Right on pages that display the account; stale verified can still win elsewhere |
| **B (shipped, `c2cc3de`)** | **hint → last_filled → verified → name** | Recency beats the sticky flag, matching Bitwarden's key order + our hint |
| C | copy the cycling shortcut | Re-press to walk matches; independent of ordering |

Recommendation: **B** was implemented, and every row is still kept (never filter
by the hint — a hint may be stale or wrong, and Bitwarden never drops rows
either). C is a UX add-on, not a fix.

## Non-goals

- No scraping of the account chip beyond the non-secret ordering hint already in
  `pageAccountHint()`.
- No change to what is filled: the hint orders rows, it never gates a fill.
