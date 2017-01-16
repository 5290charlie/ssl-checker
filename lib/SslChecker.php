<?php

date_default_timezone_set('America/Denver');

define('TIME_NOW', time());
define('DATE_FORMAT', 'Y-m-d H:i:s');

require dirname(__FILE__) . '/Colors.php';

class SslChecker {
  private $blnVerbose = false;
  private $objColors = null;
  private $arrCerts = [];
  private $arrMsgCounts = [];
  private $arrExtTypes = [
    'bundle' => 'x509',
    'csr' => 'req',
    'crt' => 'x509',
    'key' => 'rsa'
  ];

  private $arrMsgTypeColors = [
    'log' => 'white', 
    'warn' => 'yellow',
    'error' => 'red',
    'debug' => 'cyan',
    'success' => 'green'
  ];

  public function __construct() {
    $this->objColors = new Colors();
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

      $this->log('debug', "Scanning directory: {$strDir} for files: '*." . implode(', *.', $arrExtensions));

      foreach (scandir($strDir) as $strFile) {
        if ($strFile != '.' && $strFile != '..') {
          $info = pathinfo($strFile);

          $cert = $info['filename'];
          $ext = $info['extension'];

          if (in_array($ext, $arrExtensions)) {
            if (!isset($this->arrCerts[$cert])) {
              $this->arrCerts[$cert] = [];
            }

            $this->arrCerts[$cert][$ext] = $strDir . $strFile;

            $this->log('debug', "Loaded file: '{$strFile}' for cert: '{$cert}'");
          }
        }
      }
    } else {
      $this->log('error', "'{$strDir}' is not a directory!");
    }
  }

  private function processCerts() {
    foreach ($this->arrCerts as $cert => $files) {
      $this->resetMsgCounts($cert);

      $hasError = false;
      $modulus = false;

      $strPrefix = "[{$cert}]";

      $this->log('debug', "{$strPrefix} Processing " . count($files) . " file(s)", $cert);

      foreach ($files as $ext => $file) {
        if (isset($this->arrExtTypes[$ext])) {
          $type = $this->arrExtTypes[$ext];
          $hash = $this->cmd("openssl {$type} -noout -modulus -in {$file} | openssl md5");

          if ($modulus === false) {
            $modulus = $hash;
            $this->log('debug', "{$strPrefix} Stored modulus: '{$modulus}' (from file: '{$file}')", $cert);
          } else if ($modulus === $hash) {
            $this->log('debug', "{$strPrefix} Modulus for file: '{$file}' matches expected: '{$modulus}'", $cert);
          } else {
            $this->log('error', "{$strPrefix} Modulus for file: '{$file}' '{$hash}' DOES NOT MATCH expected: '{$modulus}'", $cert);
          }

          if ($type === 'x509') {
            $this->log('debug', "{$strPrefix} Checking date validity for cert file: '{$file}'", $cert);

            $dates = $this->cmd("openssl {$type} -noout -dates -in {$file}");

            $dateKeys = [
              'notBefore',
              'notAfter'
            ];

            foreach ($dateKeys as $key) {
              $regex = "/$key=(.*)(\\n)?/";
              if (preg_match($regex, $dates, $matches)) {
                if (count($matches) > 1) {
                  $date = trim($matches[1]);
                  $stamp = strtotime($date);
                  $local = date('Y-m-d H:i:s', $stamp);

                  if (($key === 'notBefore' && (TIME_NOW < $stamp)) || ($key === 'notAfter' && (TIME_NOW > $stamp))) {
                    $this->log('error', "{$strPrefix} Date is out of range! -> '{$key}' = '{$date}' (Local: '{$local}')", $cert);
                  } else {
                    $this->log('debug', "{$strPrefix} Valid for date range: '{$key}' = '{$date}' (Local: '{$local}')", $cert);
                  }
                } else {
                  $this->log('warn', "{$strPrefix} Unable to parse date key: '{$key}' from file: '{$file}'", $cert);
                }
              } else {
                $this->log('warn', "{$strPrefix} No match for regex '$regex' in dates: $dates", $cert);
              }
            }
          }
        } else {
          $this->log('warn', "{$strPrefix} No type to match extension: '{$ext}'", $cert);
        }
      }


      if ($this->arrMsgCounts[$cert]['error'] > 0 || $this->arrMsgCounts[$cert]['warn'] > 0) {
        $intNumErrors = $this->arrMsgCounts[$cert]['error'];
        $intNumWarnings = $this->arrMsgCounts[$cert]['warn'];

        $this->log('error', "{$strPrefix} Validation failed!");
        $this->log('error', "{$strPrefix} {$intNumErrors} error(s), {$intNumWarnings} warning(s)");
      } else {
        $this->log('success', "{$strPrefix} Validation successful!");
      }
    }
  }

  private function cmd($strCommand) {
    $strCommand = trim($strCommand);

    $this->log('debug', "Running command: '{$strCommand}'");

    return trim(`$strCommand`);
  }

  private function log($strType, $strMsg, $strCert = null) {
    $strType = trim(strtolower($strType));

    if ($strType !== 'debug' || $this->blnVerbose) {
      $strColor = isset($this->arrMsgTypeColors[$strType]) ? $this->arrMsgTypeColors[$strType] : null;
      $strColored = $this->objColors->getColoredString(strtoupper($strType) . "\t| " . $strMsg, $strColor);

      echo $strColored . PHP_EOL;
    }

    if ($strCert) {
      $this->arrMsgCounts[$strCert][$strType]++;
    }
  }

  private function resetMsgCounts($strCert) {
    $this->arrMsgCounts[$strCert] = [];

    foreach (array_keys($this->arrMsgTypeColors) as $strType) {
      $this->arrMsgCounts[$strCert][$strType] = 0;
    }
  }
}


