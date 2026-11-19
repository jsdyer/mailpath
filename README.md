# Mail Path

Mail Path traces the relay hops and authentication results recorded in an email’s headers. Paste the headers of a message you received, or open a local .eml or text file. The route and JSON export show reported relay addresses, timestamps, delays and recognized authentication claims.

Message files stay in the browser. Imports inspect a bounded prefix of at most 500,000 bytes. Parsing stops at the end of the header block. Reports omit message content, local mailbox identifiers and signature values. They retain relay addresses, domains and timestamps, so review an export before sharing. A paste remains visible in its input until cleared.

The app reads source claims and does not conduct cryptographic checks. A route may include forged fields or inconsistent clocks. The sources are [RFC 5321](https://www.rfc-editor.org/rfc/rfc5321) for relay traces and [RFC 8601](https://www.rfc-editor.org/rfc/rfc8601) for Authentication-Results fields. DNS Lens can inspect current public DNS policy separately.

DKIM signature fields expose their signing domains and selectors for looking up current keys in DNS Lens. The app does not retain the signature value. A current DNS key alone does not verify a message signature.

## Build and test

```sh
python3 scripts/build.py
node --test tests/*.test.mjs
python3 -m http.server --directory dist 8000
```

Deploy `dist/` to GitHub Pages. No dependency installation is required.


<!-- coolcode:guide -->
Copy the Received and Authentication-Results fields from a message you received, including indented continuation lines. The timeline shows which servers recorded each hop and the delay between their timestamps.
<!-- /coolcode:guide -->

In Gmail on a computer, open the message menu beside Reply and choose Show original. New Outlook and Outlook on the web have View message details under More actions → View. Classic Outlook for Windows puts Internet headers under File → Properties in the opened message. [Gmail instructions](https://support.google.com/mail/answer/29436?hl=en) · [Outlook instructions](https://support.microsoft.com/en-us/outlook/view-internet-message-headers-in-outlook).
