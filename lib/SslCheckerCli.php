<?php

require dirname(__FILE__) . '/../../php-cli/lib/PhpCli.php';

class SslCheckerCli extends PhpCli {
	protected $strVersion = '1.0.0';
	protected $arrAllowed = [
		'directory' => [
			'type' => 'directory',
			'default' => '.',
      'description' => 'Directory to scan for SSL cert files to be verified'
		]
	];

	private $arrCerts = [];
  private $arrMsgCounts = [];
  private $arrExtTypes = [
    'bundle' => 'x509',
    'csr' => 'req',
    'crt' => 'x509',
    'key' => 'rsa'
  ];

	public function run() {
		$this->validate($this->getOption('directory'));
	}

	public function validate($strDir) {
    $this->loadCertList($strDir);
    $this->processCerts();
  }

  private function loadCertList($strDir) {
    if (substr($strDir, -1) !== '/') {
      $strDir .= '/';
    }

    if (is_dir($strDir)) {
      $arrExtensions = array_keys($this->arrExtTypes);

      $this->debug("Scanning directory: {$strDir} for files: '*." . implode(', *.', $arrExtensions));

      foreach (scandir($strDir) as $strFile) {
        if ($strFile != '.' && $strFile != '..') {
          $arrInfo = pathinfo($strFile);

          $strCert = isset($arrInfo['filename']) ? $arrInfo['filename'] : '';
          $strExt = isset($arrInfo['extension']) ? $arrInfo['extension'] : '';

          if (in_array($strExt, $arrExtensions)) {
      			$strPrefix = "[{$strCert}]";

            if (!isset($this->arrCerts[$strCert])) {
              $this->arrCerts[$strCert] = [];
            }

            $this->arrCerts[$strCert][$strExt] = $strDir . $strFile;

            $this->debug("{$strPrefix} Loaded file: '{$strFile}'");
          }
        }
      }
    } else {
      $this->error("'{$strDir}' is not a directory!");
    }
  }

  private function processCerts() {
    foreach ($this->arrCerts as $strCert => $arrFiles) {
      $intNumErrors = 0;
      $strModulus = false;

      $strPrefix = "[{$strCert}]";

      $this->debug("{$strPrefix} Processing " . count($arrFiles) . " file(s)");

      foreach ($arrFiles as $strExt => $strFile) {
        if (isset($this->arrExtTypes[$strExt])) {
	      	$strFilename = basename($strFile);
          $strType = $this->arrExtTypes[$strExt];

          $this->debug("{$strPrefix} Validating file: {$strFilename}");

          $strHash = $this->cmd("openssl {$strType} -noout -modulus -in {$strFile} | openssl md5", $strPrefix);

          $this->debug("{$strPrefix}  Modulus: '{$strHash}'");

          if ($strModulus === false) {
            $strModulus = $strHash;
          } else if ($strModulus !== $strHash) {
          	$intNumErrors++;
            $this->error("{$strPrefix} Expected: '{$strModulus}'");
          }

          if ($strType === 'x509') {
            $strDates = $this->cmd("openssl {$strType} -noout -dates -in {$strFile}", $strPrefix);

            $strDateKeys = [
              'notBefore',
              'notAfter'
            ];

            foreach ($strDateKeys as $strKey) {
              $strRegex = "/$strKey=(.*)(\\n)?/";

              if (preg_match($strRegex, $strDates, $arrMatches)) {
                if (count($arrMatches) > 1) {
                  $strDate = trim($arrMatches[1]);
                  $intStamp = strtotime($strDate);
                  $strLocal = date('Y-m-d H:i:s', $intStamp);

                  if ($strKey === 'notBefore' && (TIME_NOW < $intStamp)) {
										$intNumErrors++;
                    $this->error("{$strPrefix} Not active until: '{$strLocal}'");
                  } else if ($strKey === 'notAfter' && (TIME_NOW > $intStamp)) {
                  	$intNumErrors++;
                    $this->error("{$strPrefix} Date is out of range! -> '{$strKey}' = '{$strDate}' (Local: '{$strLocal}')");
                  } else {
                    $this->debug("{$strPrefix} Not active since: '{$strLocal}'");
                  }
                } else {
                	$intNumErrors++;
                  $this->error("{$strPrefix} Unable to parse date key: '{$strKey}' from file: '{$strFile}'");
                }
              } else {
              	$intNumErrors++;
                $this->error("{$strPrefix} No match for regex '{$strRegex}' in dates: $strDates");
              }
            }
          }
        } else {
        	$intNumErrors++;
          $this->error("{$strPrefix} No type to match extension: '{$strExt}'");
        }
      }


      if ($intNumErrors > 0) {
        $this->error("{$strPrefix} Validation failed! {$intNumErrors} error(s)");
      } else {
        $this->success("{$strPrefix} Validation successful!");
      }
    }
  }

  private function cmd($strCommand, $strPrefix = '') {
    $strCommand = trim($strCommand);

    $this->debug("{$strPrefix} Running command: '{$strCommand}'");

    return trim(`$strCommand`);
  }
}