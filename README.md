# Atmakosh Static Website with Contact Form

Upload the contents of this folder directly into Hostinger `public_html`.

## Contact form storage

`contact-submit.php` saves submissions as JSON Lines in:

```text
../atmakosh_private/contact-submissions.jsonl
```

when permissions allow. This is outside `public_html`, which protects it from direct browser access.

If Hostinger does not allow creating a sibling folder, it falls back to:

```text
public_html/protected-data/contact-submissions.jsonl
```

That fallback folder receives an `.htaccess` deny rule.

## Security included

- Server-side validation and sanitization
- Honeypot spam field
- Minimum form-fill timing check
- Basic per-IP rate limiting
- JSONL file locking
- `.htaccess` blocks JSON/JSONL/env/log downloads
- Security headers and restrictive Content Security Policy
- Directory listing disabled

## Important

This is suitable for a simple Hostinger PHP/static deployment. For stronger protection against scraping and abuse, add Cloudflare Turnstile or reCAPTCHA, Cloudflare WAF, and email notifications.
