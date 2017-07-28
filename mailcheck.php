<?php
/**
 * MailCheck
 *
 * Provides advanced email validation including:
 * -Typo correction suggestions
 * -Text based email validation
 * -DNS based email validation
 *
 * @author Matthew Sigley, based on Mailcheck.js by Derrick Ko
 * @version 1.1
 * @license GNU GPL version 3 (or later)
 **/

 class MailCheck {
	private $allowed_mailbox_chars;
	private $allowed_domain_chars;

	private $settings;

	private $defaults = array(
		'domain_threshold' => 2,
		'second_level_threshold' => 2,
		'top_level_threshold' => 2,
		'domains' => array( 
			'msn.com', 'bellsouth.net', 'telus.net', 'comcast.net', 
			'optusnet.com.au', 'earthlink.net', 'qq.com', 'sky.com', 'icloud.com', 'mac.com', 
			'sympatico.ca', 'googlemail.com', 'att.net', 'xtra.co.nz', 'web.de', 'cox.net', 
			'gmail.com', 'ymail.com', 'aim.com', 'rogers.com', 'verizon.net', 'rocketmail.com', 
			'google.com', 'optonline.net', 'sbcglobal.net', 'aol.com', 'me.com', 'btinternet.com',
			'charter.net', 'shaw.ca', 'apple.com', 'google.com', 'hotmail.com', 'yahoo.com'
		),
		'second_level_domains' => array( 'yahoo', 'hotmail', 'mail', 'live', 'outlook', 'gmx' ),
		'top_level_domains' => array( 
			'com', 'org', 'net', 'edu', 'gov', 'mil', //Orignal TLDs
			'biz', 'info', 'me', // Most popular TLDs added in 2000
			'co', 'me', 'com.au', 'com.tw', 'ca', 'co.nz', 'co.uk', 'de', // Most ccTLDs
			'fr', 'it', 'ru', 'jp', 'nl', 'kr', 'se', 'eu', 
			'ie', 'co.il', 'us', 'at', 'be', 'dk', 'hk', 'es', 'gr', 'ch', 'no', 'cz', 
			'in', 'net.au', 'info', 'co.jp', 'sg', 'hu', 'uk' 
		)
	);

	function __construct( $args = array() ) {
		$this->settings = (object) array_merge( $this->defaults, (array) $args );
		
		// Reindex domain arrays for faster searches
		$this->settings->domains = array_combine( $this->settings->domains, $this->settings->domains );
		$this->settings->second_level_domains = array_combine( $this->settings->second_level_domains, $this->settings->second_level_domains );
		$this->settings->top_level_domains = array_combine( $this->settings->top_level_domains, $this->settings->top_level_domains );
	
		// Array filters for sanitation
		$this->allowed_mailbox_chars = array_fill_keys( range('a', 'z'), '' )
			+ array_fill_keys( range('A', 'Z'), '' )
			+ array_fill_keys( range('0', '9'), '' )
			+ array_fill_keys( str_split( "!#$%&'*+\/=?^_`{|}~.-" ), '' ) ;
		$this->allowed_domain_chars = array_fill_keys( range('a', 'z'), '' )
			+ array_fill_keys( range('A', 'Z'), '' )
			+ array_fill_keys( range('0', '9'), '' )
			+ array_fill_keys( str_split( "-." ), '' ) ;
	}
  
	// Returns suggested email
	function suggest( $original_email ) {
		$email_parts = $this->parse_email( $original_email );

		// Can't make suggestions if no domain
		if( empty( $email_parts->domain ) )
			return false;

		$valid_domain = isset( $this->settings->domains[ $email_parts->domain ] );
		$valid_sld = isset( $this->settings->second_level_domains[ $email_parts->sld ] );
		$valid_tld = isset( $this->settings->top_level_domains[ $email_parts->tld ] );

		// If email has a valid domain
		if( $valid_domain || $valid_sld && $valid_tld ) {
			// Return the sanitized email if its different than the original
			$email = $email_parts->mailbox . '@' . $email_parts->domain;
			if( $email == $original_email )
				return false;
			return $email;
		}
		
		$domain = $email_parts->domain;
		$sld = $email_parts->sld;
		$tld = $email_parts->tld;

		// Correct missing tld typos
		// Test case: test@gmail , test@yahoo.
		if( empty( $tld ) ) {
			if( $closest_domain = $this->find_closest_domain( $domain, false ) )
				return $email_parts->mailbox . '@' . $closest_domain;
			return false;
		}

		// Correct typos in tld if sld is valid and a tld was provided.
		// Handles email corrections for co.uk. 
		// Test case: test@yahoo.co.u
		if( $valid_sld && !$valid_tld ) {
			if( $closest_tld = $this->find_closest_tld( $tld ) )
				return $email_parts->mailbox . '@' . $sld . '.' . $closest_tld;
		}

		// Correct typos in sld if tld is valid.
		// Test case: test@yaho.com
		if( !$valid_sld && $valid_tld ) {
			if( $closest_sld = $this->find_closest_sld( $sld ) )
				return $email_parts->mailbox . '@' . $closest_sld . '.' . $tld;
		}

		if( $closest_domain = $this->find_closest_domain( $domain ) ) {
			return $email_parts->mailbox . '@' . $closest_domain;
		}

		$closest_sld = $this->find_closest_sld( $sld );
		$closest_tld = $this->find_closest_tld( $tld );
		
		if( !empty( $closest_sld ) || !empty( $closest_tld ) ) {
			if( !empty( $closest_sld ) )
				$sld = $closest_sld;
			if( !empty( $closest_tld ) )
				$tld = $closest_tld;

			// Return the email if its different than the original
			$email = $email_parts->mailbox . '@' . $sld . '.' . $tld;
			if( $email == $original_email )
				return false;
			return $email;
		}
		
		return false;
	}

	// Parses email into its parts.
	// Sanitizes each individual part of the email.
	function parse_email( $email ) {
		$email_parts = new StdClass();
		$email_parts->mailbox = '';
		$email_parts->domain = '';
		$email_parts->tld = '';
		$email_parts->sld = '';

		$email_parts->mailbox = $this->sanitize_email( $email );
		if( false !== strpos( $email, '@' ) ) {
			list( $mailbox, $domain ) = explode( '@', $email, 2);
			$email_parts->mailbox = $this->sanitize_mailbox($mailbox);
			$domain = $this->sanitize_domain($domain);
			if( !empty( $domain ) ) {
				$email_parts->domain = $domain;
				$email_parts->sld = $domain;
				// Techincally emails can only have a tld according to the RFC, but dotless domains are banned by ICANN
				if( strpos( $domain, '.' ) ) { 
					list( $sld, $tld ) = explode( '.', $domain, 2);
					$email_parts->sld = $sld;
					$email_parts->tld = $tld;
				}
			}
		}

		return $email_parts;
	}

	// Validation Functions
	function validate_email( $email, $validate_dns = false ) {
		$valid = (bool)filter_var($email, FILTER_VALIDATE_EMAIL);
		if( !$valid )
			return false;
		
		if( !$validate_dns )
			return true;
		
		// According to RFC2821, the domain (A record) can be treated as an
		// MX if no MX records exist for the domain. Also, include a
		// full-stop trailing char so that the default domain of the server
		// is not added automatically
		$dns_failed = false;
		list( $mailbox, $domain ) = explode( '@', $email, 2);

		set_error_handler(array($this, 'throwException'));
		try {
			// Pull all records at once to avoid multiple domain lookups
			$dns_record = dns_get_record($domain.'.', DNS_MX|DNS_A|DNS_AAAA|DNS_NS);
		} catch (Exception $e) {
			// DNS server was unreachable
			$dns_failed = true;
		}
		restore_error_handler();

		if (!$dns_failed) {
			if( empty($dns_record) )
				return false;
			$dns_record_types = array_column($dns_record, 'type');
			// Below could be multiple ands but its easier to read with if's
			if( !in_array('MX', $dns_record_types) ) { 
				if( in_array('A', $dns_record_types) || in_array('AAAA', $dns_record_types) )
					// Check for NS record for a valid domain
					// Bad DNS providers return A records for NXDOMAIN errors
					if( !in_array('NS', $dns_record_types) )
						return false;
			}
		}

		return true;
	}

	// Sanitation Functions
	function sanitize_email( $email ) {
		return filter_var($email, FILTER_SANITIZE_EMAIL);
	}

	function sanitize_mailbox( $mailbox ) {
		$mailbox = str_split( $mailbox );
		foreach( $mailbox as &$char ) {
			if( !isset( $this->allowed_mailbox_chars[ $char ] ) )
				$char = '';
		}
		return implode( '', $mailbox );
		
		//Regex equivalent of above. May be faster on newer versions of PHP with regex caching.
		//return preg_replace( '/[^a-z0-9!#$%&\'*+\/=?^_`{|}~\.-]+/i', '', $domain );
	}

	function sanitize_domain( $domain ) {
		$domain = str_split( $domain );
		foreach( $domain as &$char ) {
			if( !isset( $this->allowed_domain_chars[ $char ] ) )
				$char = '';
		}
		return implode( '', $domain );

		//Regex equivalent of above. May be faster on newer versions of PHP with regex caching.
		//return preg_replace( '/[^a-z0-9-.]+/i', '', $domain );
	}

	// String comparision functions
	function find_closest_domain( $domain, $has_dot = true ) {
		$distance = false;
		$min_distance = 99;
		$closest = false;
		$threshold = $has_dot ? $this->settings->domain_threshold : $this->settings->second_level_threshold;
		$max_threshold = floor( strlen( $domain ) / 2 );

		if( $threshold > $max_threshold )
			$threshold = $max_threshold;
		//var_dump( $threshold );

		foreach ( $this->settings->domains as $canon ) {
			if( $domain === $canon )
				return $domain;
			
			// If tld is missing, only compare slds
			if( $has_dot )
				$distance = $this->sift4( $domain, $canon );
			else
				$distance = $this->sift4( $domain, substr( $canon, 0, strpos( $canon, '.' ) ) );

			if( $distance < $min_distance ) {
				$min_distance = $distance;
				$closest = $canon;
			}
		}
		
		if( $min_distance <= $threshold && !empty( $closest ) )
			return $closest;
		
		return false;
	}

	function find_closest_sld( $sld ) {
		return $this->find_closest( $sld, $this->settings->second_level_domains, $this->settings->second_level_threshold );
	}

	function find_closest_tld( $tld ) {
		return $this->find_closest( $tld, $this->settings->top_level_domains, $this->settings->top_level_threshold );
	}

	function find_closest( $needle, $haystack, $threshold ) {
		$distance = false;
		$min_distance = 99;
		$closest = false;
		$max_threshold = floor( strlen( $needle ) / 2 );

		if( $threshold > $max_threshold )
			$threshold = $max_threshold;

		foreach ( $haystack as $canon ) {
			if( $needle === $canon )
				return $needle;
			
			$distance = $this->sift4( $needle, $canon );

			if( $distance < $min_distance ) {
				$min_distance = $distance;
				$closest = $canon;
			}
		}

		if( $min_distance <= $threshold && !empty( $closest ) )
			return $closest;
		
		return false;
	}

	// Sift4 - common version
	// online algorithm to compute the distance between two strings in O(n)
	// $maxOffset is the number of characters to search for matching letters
	// $maxDistance is the distance at which the algorithm should stop computing the value and just exit (the strings are too different anyway)
	// Props to Ferenc Szatmári via https://siderite.blogspot.com/2014/11/super-fast-and-accurate-string-distance.html#at713425542
	function sift4( $s1, $s2, $maxOffset = 5, $maxDistance = 0 ) {
		if (!$s1 || !strlen($s1)) {
				if (!$s2) {
						return 0;
				}
				return strlen($s2);
		}

		if (!$s2 || !strlen($s2)) {
				return strlen($s1);
		}

		$l1 = strlen($s1);
		$l2 = strlen($s2);

		$c1 = 0; //cursor for string 1
		$c2 = 0; //cursor for string 2
		$lcss = 0; //largest common subsequence
		$local_cs = 0; //local common substring
		$trans = 0; //number of transpositions ('ab' vs 'ba')
		$offset_arr = array(); //offset pair array, for computing the transpositions
		while (($c1 < $l1) && ($c2 < $l2)) {
				if (substr($s1, $c1, 1) == substr($s2, $c2, 1)) {
						$local_cs++;
						$isTrans = false;
						$i = 0;
						while ($i < sizeof($offset_arr)) { //see if current match is a transposition
								$ofs = $offset_arr[$i];
								if ($c1 <= $ofs['c1'] || $c2 <= $ofs['c2']) {
										$isTrans = abs($c2 - $c1) >= abs($ofs['c2'] - $ofs['c1']);
										if ($isTrans) {
												$trans++;
										} else {
												if (!$ofs['trans']) {
														$ofs['trans'] = true;
														$trans++;
												}
										}
										break;
								} else {
										if ($c1 > $ofs['c2'] && $c2 > $ofs['c1']) {
												array_splice($offset_arr, $i, 1);
										} else {
												$i++;
										}
								}
						}
						array_push($offset_arr, array('c1' => $c1, 'c2' => $c2, 'trans' => $isTrans));
				} else {
						$lcss += $local_cs;
						$local_cs = 0;
						if ($c1 != $c2) {
								$c1 = $c2 = min($c1, $c2); //using min allows the computation of transpositions
						}
						//if matching characters are found, remove 1 from both cursors (they get incremented at the end of the loop)
						//so that we can have only one code block handling matches
						for ($i = 0; $i < $maxOffset && ($c1 + $i < $l1 || $c2 + $i < $l2); $i++) {
								if (($c1 + $i < $l1) && (substr($s1, $c1 + $i, 1) == substr($s2, $c2, 1))) {
										$c1 += $i - 1;
										$c2--;
										break;
								}
								if (($c2 + $i < $l2) && (substr($s1, $c1, 1) == substr($s2, $c2 + $i, 1))) {
										$c1--;
										$c2 += $i - 1;
										break;
								}
						}
				}
				$c1++;
				$c2++;
				if ($maxDistance) {
						$temporaryDistance = max($c1, $c2) - $lcss + $trans;
						if ($temporaryDistance >= $maxDistance)
								return $temporaryDistance;
				}
				// this covers the case where the last match is on the last token in list, so that it can compute transpositions correctly
				if (($c1 >= $l1) || ($c2 >= $l2)) {
						$lcss += $local_cs;
						$local_cs = 0;
						$c1 = $c2 = min($c1, $c2);
				}
		}
		$lcss += $local_cs;
		return max($l1, $l2) - $lcss + $trans; //apply transposition cost to final result
	}

	function throwException($severity, $message, $file, $line) {
		if (!(error_reporting() & $severity)) {
			// This error code is not included in error_reporting
			return;
		}
        throw new ErrorException($message, 0, $severity, $file, $line);
  }
 }
