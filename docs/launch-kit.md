# Launch kit

Drafts for sharing legalPrivacy. Everything here is for a person to post; nothing is posted automatically.

## Before posting anywhere

- Read the venue's current rules the same day. Rules change and I have only read Hacker News's Show HN page (https://news.ycombinator.com/showhn.html).
- Post as yourself, say you made it, stay around to answer, and never ask friends to upvote (Hacker News says this is not allowed).
- Link the release, not a landing page: https://github.com/asonpeikoff/legalprivacy/releases (Linux file `legalprivacy-launch-linux`).
- Use screenshots from `docs/screenshots/` and the infographic.
- Say plainly what it does not do (see "Honest limits" below). It is the thing technical readers check first.

## One-line pitch

Believable background browsing, searches and DNS lookups, so bulk analysis of your traffic tells much less about you. It measures itself and corrects the gap.

## Show HN draft

**Title:** Show HN: legalPrivacy – cover traffic that measures how much it looks like you

**First comment (from the author):**

> I made this because the usual advice for traffic analysis is to hide, and I wanted to see how far making noise that actually looks like you could go. It runs on your own computer and sends page visits, searches and DNS lookups that scroll, read and pause like a person, through a real browser. DNS lookups come with the burst of lookups a page load makes. Searches arrive in related runs, not alone.
>
> The part I care about most is the measuring. A Proof tab compares the rhythm of the noise with your own traffic (time of day, burst length, quiet gaps, busyness) with a percent difference and a p-value, and an "adjust to my rhythm" option plans more noise in the hours you are away. An ML tab trains a classifier to tell the noise from you and says which habit gives you away.
>
> Limits: it adds cover traffic; it does not hide your IP or make you anonymous, it does not defeat an observer who sees both ends of a connection, and the scores are estimates (the p-values treat minutes as independent, which they are not). Linux download is on the releases page; it also runs from source elsewhere. Tor, bridges and a Tor Browser button are optional.
>
> I'd like to hear where the self-test is wrong or what gives the noise away.

## Short post (forums that allow announcements)

> **legalPrivacy** is a free, open-source app that adds believable background traffic (real-browser visits, searches, DNS) so bulk analysis of your browsing is less reliable. It shows its own evidence: a live network map, a rhythm comparison with p-values, and a classifier that tries to tell the noise from you. Optional Tor with bridges, offline antivirus scanning, three panic levels. Honest limits are in the README. Feedback welcome.
> https://github.com/asonpeikoff/legalprivacy

## Places that look relevant (check each one's rules first)

| Place | Why | Note |
|---|---|---|
| Hacker News, Show HN | Technical audience, a tool people can try | Rules read above. Post yourself; do not solicit votes. |
| Privacy Guides forum | Privacy-focused readers | It has a guidelines page: https://discuss.privacyguides.net/guidelines (not read yet). |
| r/PrivacyGuides, r/privacytoolsIO | Privacy communities on Reddit | Rules not read; many subreddits restrict self-promotion. |
| Lobsters | Technical link aggregator | Needs an invitation; guidelines not read. |
| awesome-privacy (lissy93) | A curated GitHub list | Submit a pull request following its contributing guide: https://github.com/lissy93/awesome-privacy |

## Honest limits (keep these in every post)

- Cover traffic, not anonymity.
- Not a defence against flow correlation.
- Scores and p-values are estimates from the user's own data.
- The plain HTTP lane has a different TLS handshake from a browser and is off by default.
- Ready-made downloads are Linux only for now.
