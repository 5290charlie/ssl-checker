# ssl-checker
Validate SSL request, certificate, &amp; key files (verify both modulus &amp; date)

## Usage

### Executable PHP script
- Must have php executable: `/usr/bin/php`
- Script can be executed relative to this path:
	- `$ ./path/to/ssl-checker/bin/ssl-checker <directory-to-check>`
- Or, can be linked to be visible in `PATH`
	- `$ sudo ln -s ./path/to/ssl-checker/bin/ssl-checker /usr/local/bin/ssl-checker`
	- `$ ssl-checker <directory-to-check>`

### Include in PHP code
```php
<?php

require 'path/to/ssh-checker/lib/SslChecker.php';

$myChecker = new SslChecker();

$myChecker->validate('/etc/nginx/certs');
```
