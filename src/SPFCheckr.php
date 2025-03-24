<?php

use Exception;

class SPFResult
{
    /**
     * Something went wrong during the SPF Check.
     * @var string
     */
    public  $ERROR = 'ERROR';

    /**
     * The email message comes from a legitimate source.
     * @var string
     */
    public $SPF_PASS = 'SPF_PASS';

    /**
     * In this case, the email message hasn’t come from a legitimate source, due to which it will get rejected.
     * @var string
     */
    public $SPF_FAIL = 'SPF_FAIL';

    /**
     * In this case, the email neither passes nor fails authentication checks since the SPF
     * record doesn’t explicitly state whether the sender is authorized to send messages.
     * @var string
     */
    public $SPF_NEUTRAL = 'SPF_NEUTRAL';

    /**
     * The recipient’s server accepts the message failing SPF authentication checks,
     * but it will land in the spam folder.
     * @var string
     */
    public $SPF_SOFTFAIL = 'SPF_SOFTFAIL';
}

class SPFCheckr
{
    /**
     * The domain name of the sender.
     *
     * @var string
     */
    private $domain;

    /**
     * The IP address of the Mail server that is emitting the mail.
     *
     * @var string
     */
    private $ip;

    /**
     * The all flag if the IP is not in the list of the ones allowed.
     *
     * @var string
     */
    private $errorFlag;

    /**
     * Initialize the instance.
     *
     * @param string $senderDomain the DOMAIN of the sender in the MAIL header.
     * @param string $senderIP the IP of the server from which we received the mail.
     */
    public function __construct(string $senderDomain, string $senderIP)
    {
        $this->ip = $senderIP;
        $this->domain = $senderDomain;
    }

    protected function getIP(): string
    {
        return $this->ip;
    }

    protected function getDomain(): string
    {
        return $this->domain;
    }

    protected function getErrorFlag(): string
    {
        return $this->errorFlag;
    }

    /**
     * Pass the IP and Domain in the SPF Checker.
     *
     * Returns the SPF Flag.
     */
    public function passes()
    {
        if ($this->checkExistenceOfDomain($this->getDomain())) {
            $spfRecord = $this->getSPFRecord($this->getDomain());
            if ($this->isFound($spfRecord)) {
                $spfInfos= $this->extractInfosForSPFRecord($spfRecord);
                if ($this->checkIPinAllowedIPs($spfInfos, $this->getIP())) {
                    return SPFResult::$SPF_PASS;
                } else if ($this->getErrorFlag()) {
                    return $this->handleSPFResult();
                }
                return SPFResult::$ERROR;
            }
        }

        return SPFResult::$ERROR;
    }

    /**
     * @throws Exception
     */
    public function isFound(string $result): bool
    {
        return ($result !== 'Not found!');
    }

    /**
     * @throws Exception
     */
    public function handleSPFResult(): string
    {
        switch ($this->errorFlag) {
            case '+':
                return SPFResult::$SPF_PASS;
            case '-':
                return SPFResult::$SPF_FAIL;
            case '?':
                return SPFResult::$SPF_NEUTRAL;
            case '~':
                return SPFResult::$SPF_SOFTFAIL;
            default:
                break;
        }

        return SPFResult::$ERROR;
    }

    /**
     * @throws Exception
     */
    public function extractSenderDomainName(string $fileContent): string
    {
        if (strpos($fileContent, "MAIL FROM") !== false) {
            $lines = explode("\n", $fileContent);

            foreach ($lines as $line) {
                if (strpos($line, 'MAIL FROM') !== false) {
                    $sender = trim($line);
                    if (preg_match('/@([a-zA-Z0-9.-]+)/', $sender, $matches)) {
                        $senderDomain = $matches[1];
                        return $senderDomain;
                    } else {
                        return "Not found!";
                    }
                }
            }
        }

        return "Not found!";
    }

    /**
     * @throws Exception
     */
    public function extractSenderIP(string $fileContent): string
    {
        if (strpos($fileContent, "XFORWARD ADDR=") !== false) {
            $lines = explode("\n", $fileContent);

            foreach ($lines as $line) {
                if (strpos($line, 'XFORWARD ADDR=') !== false) {
                    $ip = trim($line);
                    if (preg_match('/XFORWARD ADDR=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/', $ip, $matches)) {
                        $senderIP = $matches[1];
                        return $senderIP;
                    } else {
                        return "Not found!";
                    }
                }
            }
        }

        return "Not found!";
    }

    /**
     * @throws Exception
     */
    public function extractIPs(string $spfRecord): array
    {
        preg_match_all('/(?:ip4|ip6)\\s*:\\s*([0-9a-fA-F.:\/]+)/i', $spfRecord, $matches);
        return array_values(array_filter($matches[1]));
    }

    /**
     * @throws Exception
     */
    public function extractIncludes(string $spfRecord): array
    {
        $cleanedSPF = trim($spfRecord, "\" \t\n\r\0\x0B");
        preg_match_all('/include\\s*:\\s*([a-zA-Z0-9._-]+)/i', $cleanedSPF, $matches);
        return array_values(array_filter($matches[1]));
    }

    /**
     * @throws Exception
     */
    public function extractRedirect(string $spfRecord): ?string
    {
        if (preg_match('/redirect\\s*=\\s*([a-zA-Z0-9._-]+)/i', $spfRecord, $match)) {
            return $match[1];
        }
        return null;
    }

    /**
     * @throws Exception
     */
    public function extractA(string $spfRecord): array
    {
        preg_match_all('/a\\s*:\\s*([a-zA-Z0-9._-]+)/i', $spfRecord, $matches);
        return array_values(array_filter($matches[1]));
    }

    /**
     * @throws Exception
     */
    public function extractMX(string $spfRecord): array
    {
        if (preg_match('/mx(?::([a-zA-Z0-9._-]+))?/i', $spfRecord, $match)) {
            if ($this->checkExistenceOfMX($this->actualDomain)) {
                $mxs = $this->getMXRecord($this->actualDomain);
                if (gettype($mxs) === 'string') {
                    return [$mxs];
                }
                return $mxs;
            }
        }
        return [];
    }

    /**
     * @throws Exception
     */
    public function extractAllFlag(string $spfRecord): ?string
    {
        if (preg_match('/([+\-~?]?)all\b/i', $spfRecord, $match)) {
            $this->errorFlag = $match[1][0];
        }
        return null;
    }

    /**
     * @throws Exception
     */
    public function checkExistenceOfDomain(string $domain): bool
    {
        return checkdnsrr($domain, "TXT");
    }

    /**
     * @throws Exception
     */
    public function checkExistenceOfMX(string $domain): bool
    {
        return checkdnsrr($domain, "MX");
    }

    /**
     * @throws Exception
     */
    public function checkExistenceOfA(string $domain): bool //IPv4
    {
        return checkdnsrr($domain, "A");
    }

    /**
     * @throws Exception
     */
    public function checkExistenceOfAAAA(string $domain): bool //IPv6
    {
        return checkdnsrr($domain, "AAAA");
    }

    /**
     * @throws Exception
     */
    public function getSubDomainIps(string $subdomain): array
    {
        $ips = [];

        if ($this->checkExistenceOfA($subdomain)) {
            $domainIPv4s = $this->getARecord($subdomain);
            $ips = array_unique(array_merge($ips, $domainIPv4s));
        }
        if ($this->checkExistenceOfAAAA($subdomain)) {
            $domainIPv6s = $this->getAAAARecord($subdomain);
            $ips = array_unique(array_merge($ips, $domainIPv6s));
        }

        return $ips;
    }

    /**
     * @throws Exception
     */
    public function isIPv4Allowed(array $IPsv4, string $ip): bool
    {
        foreach ($IPsv4 as $allowedIp) {
            if ($ip === $allowedIp) {
                return true;
            }

            if (strpos($allowedIp, '/')) {
                list($subnet, $maskLength) = explode('/', $allowedIp);

                $ipLong = ip2long($ip);
                $subnetLong = ip2long($subnet);
                $mask = -1 << (32 - $maskLength);
                $subnetMask = $subnetLong & $mask;

                if (($ipLong & $mask) === $subnetMask) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * @throws Exception
     */
    public function isIPv6Allowed(array $IPsv6, string $ip): bool
    {
        $ipBin = inet_pton($ip);

        if ($ipBin === false) {
            return false;
        }

        foreach ($IPsv6 as $allowedIp) {
            if ($ip === $allowedIp) {
                return true;
            }

            if (strpos($allowedIp, '/') === false) {
                continue;
            }

            list($subnet, $maskLength) = explode('/', $allowedIp);

            $subnetBin = inet_pton($subnet);

            if ($subnetBin === false) {
                continue;
            }

            $ipBits = unpack('H*', $ipBin)[1];
            $subnetBits = unpack('H*', $subnetBin)[1];

            $bitsToCheck = intval($maskLength / 4);
            $bitsRemain = $maskLength % 4;

            $ipPrefix = substr($ipBits, 0, $bitsToCheck);
            $subnetPrefix = substr($subnetBits, 0, $bitsToCheck);

            if ($ipPrefix !== $subnetPrefix) {
                continue;
            }

            if ($bitsRemain === 0) {
                return true;
            }

            $ipNibble = hexdec($ipBits[$bitsToCheck]);
            $subnetNibble = hexdec($subnetBits[$bitsToCheck]);

            $mask = (0xf0 >> ($bitsRemain - 1)) & 0x0f;

            if (($ipNibble & $mask) === ($subnetNibble & $mask)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @throws Exception
     */
    public function checkIPinAllowedIPs($infos, $senderIP)
    {
        if (filter_var(explode('/', $senderIP)[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return $this->isIPv4Allowed($infos['ipv4'], $senderIP);
        } else if (filter_var(explode('/', $senderIP)[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return $this->isIPv6Allowed($infos['ipv6'], $senderIP);
        }

        return false;
    }

    /**
     * @throws Exception
     */
    public function getSPFRecord($domain) {
        $records = dns_get_record($domain, DNS_TXT);
        foreach ($records as $record) {
            if (isset($record['txt']) && strpos($record['txt'], 'v=spf1') === 0) {
                return $record['txt'];
            }
        }
        return 'Not Found';
    }

    /**
     * @throws Exception
     */
    public function getMXRecord($domain) {
        $records = dns_get_record($domain, DNS_MX);
        $res = [];
        foreach ($records as $record) {
            if (isset($record['target'])) {
                array_push($res, $record['target']);
            }
        }
        return $res;
    }

    /**
     * @throws Exception
     */
    public function getARecord(string $domain): array {
        $records = dns_get_record($domain, DNS_A);
        $res = [];
        foreach ($records as $record) {
            if (isset($record['ip'])) {
                array_push($res, $record['ip']);
            }
        }
        return $res;
    }

    /**
     * @throws Exception
     */
    public function getAAAARecord(string $domain): array {
        $records = dns_get_record($domain, DNS_AAAA);
        $res = [];
        foreach ($records as $record) {
            if (isset($record['ipv6'])) {
                array_push($res, $record['ipv6']);
            }
        }
        return $res;
    }

    /**
     * @throws Exception
     */
    public function parseSPF(string $spfRecord): array
    {
        $ips = $this->extractIPs($spfRecord);
        $includes = $this->extractIncludes($spfRecord);
        $redirect = $this->extractRedirect($spfRecord);
        $mx = $this->extractMX($spfRecord);
        $a = $this->extractA($spfRecord);

        if ($mx) {
            foreach ($mx as $mxDomain) {
                $mxIPs = $this->getSubDomainIPs($mxDomain);
                if ($mxIPs) {
                    $ips = array_unique(array_merge($ips, $mxIPs));
                }
            }
        }
        if ($a) {
            foreach ($a as $aDomain) {
                $aIPs = $this->getSubDomainIPs($aDomain);
                if ($aIPs) {
                    $ips = array_unique(array_merge($ips, $aIPs));
                }
            }
        }

        $domains = $includes;
        if ($redirect) {
            $domains[] = $redirect;
        }
        if ($mx) {
            $domains = array_unique(array_merge($domains, $mx));
        }
        if ($a) {
            $domains = array_unique(array_merge($domains, $a));
        }

        return [
            'ips' => $ips,
            'domains' => array_unique($domains)
        ];
    }

    /**
     * @throws Exception
     */
    public function resolveIncludeSPF($includes, &$visited = []) {
        $allIPs = [];
        $allDomains = [];

        foreach ($includes as $include) {
            if (in_array($include, $visited)) {
                continue;
            }

            $visited[] = $include;
            $allDomains[] = $include;

            $spf = $this->getSPFRecord($include);
            $this->actualDomain = $include;
            if ($spf) {
                if (!$this->errorFlag) {
                    $this->extractAllFlag($spf);
                }

                $parsedSPF = $this->parseSPF($spf);

                $allIPs = array_merge($allIPs, $parsedSPF['ips']);

                $subIncludes = $this->resolveIncludeSPF($parsedSPF['domains'], $visited);

                $allIPs = array_merge($allIPs, $subIncludes['ips']);
                $allDomains = array_merge($allDomains, $subIncludes['domains']);
            }
        }

        return [
            'ips' => $allIPs,
            'domains' => array_unique($allDomains),
        ];
    }

    /**
     * @throws Exception
     */
    public function extractInfosForSPFRecord($spfRecord) {
        $parsedSPF = $this->parseSPF($spfRecord);

        $resolvedIncludeIPs = $this->resolveIncludeSPF($parsedSPF['domains']);
        $allIPs = array_unique(array_merge($parsedSPF['ips'], $resolvedIncludeIPs['ips']));

        $allDomains = array_unique(array_merge([$this->fromDomain], array_merge($parsedSPF['domains'], $resolvedIncludeIPs['domains'])));

        $domainIPs = $this->getSubDomainIps($this->fromDomain);
        if ($domainIPs) {
            $allIPs = array_unique(array_merge($allIPs, $domainIPs));
        }

        $ipv4 = [];
        $ipv6 = [];

        foreach ($allIPs as $ip) {
            if (filter_var(explode('/', $ip)[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $ipv4[] = $ip;
            } else if (filter_var(explode('/', $ip)[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                $ipv6[] = $ip;
            }
        }

        return [
            'ipv4' => $ipv4,
            'ipv6' => $ipv6,
            'domains' => $allDomains
        ];
    }
}
