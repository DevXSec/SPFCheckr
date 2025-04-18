<?php

class SPFResult
{
    /**
     * Something went wrong during the SPF Check.
     * @var string
     */
    public static $ERROR = 'ERROR';

    /**
     * The email message comes from a legitimate source.
     * @var string
     */
    public static $SPF_PASS = 'SPF_PASS';

    /**
     * In this case, the email message hasn’t come from a legitimate source, due to which it will get rejected.
     * @var string
     */
    public static $SPF_FAIL = 'SPF_FAIL';

    /**
     * In this case, the email neither passes nor fails authentication checks since the SPF
     * record doesn’t explicitly state whether the sender is authorized to send messages.
     * @var string
     */
    public static $SPF_NEUTRAL = 'SPF_NEUTRAL';

    /**
     * The recipient’s server accepts the message failing SPF authentication checks,
     * but it will land in the spam folder.
     * @var string
     */
    public static $SPF_SOFTFAIL = 'SPF_SOFTFAIL';
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
     * The option if the IP is IPv4 or IPv6 to make the SPF check.
     * @var string
     */
    private $option;

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
        $this->domain = $senderDomain;
        $this->ip = $senderIP;
        if (filter_var($senderIP, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $this->setOption("IPv4");
        } else if (filter_var($senderIP, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $this->setOption("IPv6");
        }
    }

    protected function getIP(): string
    {
        return $this->ip;
    }

    protected function getDomain(): string
    {
        return $this->domain;
    }

    protected function getOption(): string
    {
        return $this->option;
    }

    protected function setOption(string $option): void
    {
        $this->option = $option;
    }

    protected function getErrorFlag(): ?string
    {
        return $this->errorFlag;
    }

    protected function setErrorFlag(string $errorFlag): void
    {
        $this->errorFlag = $errorFlag;
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
                $spfInfos = $this->extractInfosForSPFRecord($spfRecord);
                if ($this->checkIPinAllowedIPs($spfInfos, $this->getIP())) {
                    return SPFResult::$SPF_PASS;
                }
                return $this->handleSPFResult();
            }
        }

        return SPFResult::$ERROR;
    }


    /*
    =============================
    =           Utils           =
    =============================
    */


    /**
     * Checks something was found from the dns functions.
     *
     * @param string $result The result of other functions.
     */
    public function isFound(string $result): bool
    {
        return ($result !== 'Not found!');
    }

    /**
     * Handle the "all" flag if IP wasn't found
     */
    public function handleSPFResult(): string
    {
        switch ($this->getErrorFlag()) {
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

        return SPFResult::$SPF_FAIL;
    }


    /*
    =============================
    =Extractions from SPF Record=
    =============================
    */


    /**
     * Extracts the IPs (IPv4/IPv6) from the spf record.
     *
     * @param string $spfRecord from getSPFRecord.
     */
    public function extractIPs(string $spfRecord): array
    {
        preg_match_all('/(?:ip4|ip6)\\s*:\\s*([0-9a-fA-F.:\/]+)/i', $spfRecord, $matches);
        return array_values(array_filter($matches[1]));
    }

    /**
     * Extracts the included subdomains in the spf record.
     *
     * @param string $spfRecord from getSPFRecord.
     */
    public function extractIncludes(string $spfRecord): array
    {
        preg_match_all('/include\\s*:\\s*([a-zA-Z0-9._-]+)/i', $spfRecord, $matches);
        return array_values(array_filter($matches[1]));
    }

    /**
     * Extracts the redirection to domain in the spf record.
     *
     * @param string $spfRecord from getSPFRecord.
     */
    public function extractRedirect(string $spfRecord): array
    {
        preg_match_all('/redirect\\s*=\\s*([a-zA-Z0-9._-]+)/i', $spfRecord, $matches);
        return array_values(array_filter($matches[1]));
    }

    /**
     * Extracts the "a" (list of IPs for a domain) in the spf record.
     *
     * @param string $spfRecord from getSPFRecord.
     */
    public function extractA(string $spfRecord): array
    {
        preg_match_all('/a\\s*:\\s*([a-zA-Z0-9._-]+)/i', $spfRecord, $matches);
        return array_values(array_filter($matches[1]));
    }

    /**
     * Extracts the "mx" (mailer exchange) in the spf record.
     *
     * @param string $spfRecord from getSPFRecord.
     * @param string $domain from which we are performing the spf record look up.
     */
    public function extractMX(string $spfRecord, string $domain): array
    {
        if (preg_match('/mx(?::([a-zA-Z0-9._-]+))?/i', $spfRecord, $match)) {
            if ($this->checkExistenceOfMX($domain)) {
                $mxs = $this->getMXRecord($domain);
                if (gettype($mxs) === 'string') {
                    return [$mxs];
                }
                return $mxs;
            }
        }
        return [];
    }

    /**
     * Extracts the "all" flag (muse to handle the SPF response if IP doesn't match) in the spf record.
     *
     * @param string $spfRecord from getSPFRecord.
     */
    public function extractAllFlag(string $spfRecord): void
    {
        if (preg_match('/([+\-~?]?)all\b/i', $spfRecord, $match)) {
            $this->setErrorFlag($match[1][0]);
        }
    }


    /*
    =============================
    =          Checks           =
    =============================
    */
    

    /**
     * Checks if a domain exists.
     *
     * @param string $domain for which we are performing the check.
     */
    public function checkExistenceOfDomain(string $domain): bool
    {
        return checkdnsrr($domain, "TXT");
    }

    /**
     * Checks if a mail exchange server exists for this domain.
     *
     * @param string $domain for which we are performing the check.
     */
    public function checkExistenceOfMX(string $domain): bool
    {
        return checkdnsrr($domain, "MX");
    }

    /**
     * Checks if a record of IPv4 (a) is listed for this domain.
     *
     * @param string $domain for which we are performing the check.
     */
    public function checkExistenceOfA(string $domain): bool
    {
        return checkdnsrr($domain, "A");
    }

    /**
     * Checks if a record of IPv6 (aaaa) is listed for this domain.
     *
     * @param string $domain for which we are performing the check.
     */
    public function checkExistenceOfAAAA(string $domain): bool
    {
        return checkdnsrr($domain, "AAAA");
    }


    /*
    =============================
    =            IPs            =
    =============================
    */


    /**
     * Get the IPs of the domain.
     *
     * @param string $domain for which we are performing the check.
     * @param string $option if we are looking for IPv4 or IPv6.
     */
    public function getDomainIps(string $domain): array
    {
        $ips = [];
    
        switch ($this->getOption()) {
            case 'IPv4':
                if ($this->checkExistenceOfA($domain)) {
                    $domainIPv4s = $this->getARecord($domain);
                    $ips = array_unique(array_merge($ips, $domainIPv4s));
                }
                break;
            case 'IPv6':
                if ($this->checkExistenceOfAAAA($domain)) {
                    $domainIPv6s = $this->getAAAARecord($domain);
                    $ips = array_unique(array_merge($ips, $domainIPv6s));
                }
                break;
            default:
                break;
        }

        return $ips;
    }

    /**
     * Check if our IP is in the IPv4 list.
     *
     * @param array $IPsv4 extracted from the checks for the domain and subdomains.
     */
    public function isIPv4Allowed(array $IPsv4): bool
    {
        $ip = $this->getIP();
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
     * Check if our IP is in the IPv6 list.
     *
     * @param array $IPsv6 extracted from the checks for the domain and subdomains.
     */
    public function isIPv6Allowed(array $IPsv6): bool
    {
        $ip = $this->getIP();

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
     * Check which method to use depending of our IP type.
     *
     * @param array $domainIPs extracted from the checks for the domain and subdomains.
     */
    public function checkIPinAllowedIPs($domainIPs): bool
    {
        switch ($this->getOption())
        {
            case 'IPv4':
                return $this->isIPv4Allowed($domainIPs);
            case 'IPv6':
                return $this->isIPv6Allowed($domainIPs);
            default:
                break;
        }

        return false;
    }


    /*
    =============================
    = Get Records for a domain  =
    =============================
    */


    /**
     * Get the SPF Record from our specified domain.
     *
     * @param string $domain from which we want to extract the spf record.
     */
    public function getSPFRecord(string $domain): string
    {
        $records = dns_get_record($domain, DNS_TXT);
        foreach ($records as $record) {
            if (isset($record['txt']) && strpos($record['txt'], 'v=spf1') === 0) {
                return $record['txt'];
            }
        }
    
        return 'Not Found';
    }

    /**
     * Get the MX Records from our specified domain.
     *
     * @param string $domain from which we want to extract the mx record.
     */
    public function getMXRecord(string $domain) {
        $res = [];
        $records = dns_get_record($domain, DNS_MX);
        foreach ($records as $record) {
            if (isset($record['target'])) {
                array_push($res, $record['target']);
            }
        }
    
        return $res;
    }

    /**
     * Get the A (IPv4) Records from our specified domain.
     *
     * @param string $domain from which we want to extract the A (IPv4) record.
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
     * Get the AAAA (IPv6) Records from our specified domain.
     *
     * @param string $domain from which we want to extract the AAAA (IPv6) record.
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

    /*
    =============================
    =       Parsing Infos       =
    =============================
    */

    /**
     * Extract the IPv4s or IPv6s of the array of IPs.
     *
     * @param array $ips the ips extracted from the spf check.
     */
    public function parseIPs(array $ips): array
    {
        $parsedIPs = [];

        switch ($this->getOption())
        {
            case 'IPv4':
                foreach ($ips as $ip) {
                    if (filter_var(explode('/', $ip)[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                        $parsedIPs[] = $ip;
                    }
                }
                break ;
            case 'IPv6':
                foreach ($ips as $ip) {
                    if (filter_var(explode('/', $ip)[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                        $parsedIPs[] = $ip;
                    }
                }
                break ;
            default:
                break;
        }

        return $parsedIPs;
    }

    /**
     * Extract the infos (ips and domains (includes, a, redirect)) of the SPF Record and domain.
     *
     * @param string $spfRecord the result from getSPFRecord.
     * @param string $domain the domain for which we are checking the spf record.
     */
    public function parseSPF(string $spfRecord, string $domain): array
    {
        $ips = $this->extractIPs($spfRecord);
        $includes = $this->extractIncludes($spfRecord);
        $redirect = $this->extractRedirect($spfRecord);
        $mx = $this->extractMX($spfRecord, $domain);
        $a = $this->extractA($spfRecord);

        if ($mx) {
            foreach ($mx as $mxDomain) {
                $mxIPs = $this->getDomainIps($mxDomain);
                if ($mxIPs) {
                    $ips = array_unique(array_merge($ips, $mxIPs));
                }
            }
        }
        if ($a) {
            foreach ($a as $aDomain) {
                $aIPs = $this->getDomainIps($aDomain);
                if ($aIPs) {
                    $ips = array_unique(array_merge($ips, $aIPs));
                }
            }
        }


        $domains = $includes;
        if ($redirect) {
            $domains = array_unique(array_merge($domains, $redirect));
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


    /*
    =============================
    =         Resolvers         =
    =============================
    */


    /**
     * Extract the IPv4s or IPv6s of the SPF Record depending on the domain.
     *
     * @param array $includes the domains that we extracted from the parseSPF.
     * @param array $vistied to make it recursive and keep them in mind.
     */
    public function resolveIncludeDomainsIPs(array $includes, &$visited = []): array
    {
        $allIPs = [];
        $allDomains = [];

        foreach ($includes as $include) {
            if (in_array($include, $visited)) {
                continue;
            }

            $visited[] = $include;

            $spf = $this->getSPFRecord($include);
            if ($spf) {
                if ($this->getErrorFlag() === null) {
                    $this->extractAllFlag($spf);
                }

                $parsedSPF = $this->parseSPF($spf, $include);

                $allIPs = array_merge($allIPs, $this->parseIPs($parsedSPF['ips']));
                $subIncludes = $this->resolveIncludeDomainsIPs($parsedSPF['domains'], $visited);
                $allIPs = array_merge($allIPs, $this->parseIPs($subIncludes['ips']));
            }
        }

        return [
            'ips' => $allIPs,
            'domains' => array_unique($visited),
        ];
    }

    /**
     * Extract the IPv4s or IPv6s of the SPF Record depending on the domain.
     *
     * @param string $spfRecord that we extracted from the getSPFRecord.
     */
    public function extractInfosForSPFRecord(string $spfRecord): array
    {
        $parsedSPF = $this->parseSPF($spfRecord, $this->getDomain());

        $resolvedIncludeIPs = $this->resolveIncludeDomainsIPs($parsedSPF['domains']);
        $ips = array_unique(array_merge($parsedSPF['ips'], $resolvedIncludeIPs['ips']));

        $domainIPs = $this->getDomainIps($this->getDomain());
        if ($domainIPs) {
            $ips = array_unique(array_merge($ips, $domainIPs));
        }

        return $ips;
    }
}
