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
 * @version 1.3
 * @license GNU GPL version 3 (or later)
 **/

 class MailCheck {
	private $allowed_mailbox_chars;
	private $allowed_domain_chars;

	private $settings;

	private $dns_cache = array();

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
			'charter.net', 'shaw.ca', 'apple.com', 'google.com', 'hotmail.com', 'yahoo.com',
			'outlook.com', 'googlemail.com',
			// Top 20 Mail.com domains https://www.mail.com/email/#.7518-header-subnav1-4
			'mail.com', 'email.com', 'usa.com', 'myself.com', 'consultant.com', 'post.com',
			'europe.com', 'asia.com', 'iname.com', 'writeme.com', 'dr.com', 'cheerful.com', 
			'accountant.com', 'techie.com', 'engineer.com', 'linuxmail.org', 'musician.org',
			'contractor.net', 'financier.com', 'workmail.com'
		),
		'second_level_domains_overrides' => array( 
			// Gmail is always gmail.com
			// https://www.gmass.co/blog/domains-gmail-com-googlemail-com-and-google-com/
			'gmail' => 'gmail.com', 'googlemail' => 'googlemail.com'
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
	public function suggest( $original_email ) {
		$email_parts = $this->parse_email( $original_email );

		// Can't make suggestions if no domain
		if( empty( $email_parts->domain ) )
			return false;

		$valid_domain = isset( $this->settings->domains[ $email_parts->domain ] );
		$valid_sld = isset( $this->settings->second_level_domains[ $email_parts->sld ] );
		$valid_tld = isset( $this->settings->top_level_domains[ $email_parts->tld ] );

		// If email has a valid domain
		$valid = false;
		if( $valid_domain ) {
			$valid = true;
		} elseif( isset( $this->settings->second_level_domains_overrides[$email_parts->sld] ) ) {
			$valid = true;
			$email_parts->domain = $this->settings->second_level_domains_overrides[$email_parts->sld];
		} elseif( $domain = $this->find_one_character_off( $email_parts->domain, $this->settings->domains ) ) {
			$valid = true;
			$email_parts->domain = $domain;
		} elseif( $valid_sld && $valid_tld ) {
			$valid = true;
		}

		if( $valid ) {
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
	public function parse_email( $email ) {
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
	public function validate_email( $email, $validate_dns = false ) {
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

		if( isset( $this->dns_cache[$domain] ) )
			return $this->dns_cache[$domain];

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
			if( function_exists( 'array_column' ) )
				$dns_record_types = array_column($dns_record, 'type');
			else
				$dns_record_types = array_map( function($element) { return $element['type']; }, $dns_record );
			// Below could be multiple ands but its easier to read with if's
			if( !in_array('MX', $dns_record_types) ) { 
				$email_parts = $this->parse_email( $email );

				if( isset( $this->settings->second_level_domains_overrides[$email_parts->sld] ) 
					|| $this->find_one_character_off( $email_parts->domain, $this->settings->domains ) ) {
					$this->dns_cache[$domain] = false;
					return false;
				}

				if( in_array('A', $dns_record_types) || in_array('AAAA', $dns_record_types) ) {
					// Check for NS record for a valid domain
					// Bad DNS providers return A records for NXDOMAIN errors
					if( !in_array('NS', $dns_record_types) ) {
						$this->dns_cache[$domain] = false;
						return false;
					}
				}
			}
		}

		$this->dns_cache[$domain] = true;
		return true;
	}

	// Sanitation Functions
	public function sanitize_email( $email ) {
		return filter_var($email, FILTER_SANITIZE_EMAIL);
	}

	public function sanitize_mailbox( $mailbox ) {
		$mailbox = str_split( $mailbox );
		foreach( $mailbox as &$char ) {
			if( !isset( $this->allowed_mailbox_chars[ $char ] ) )
				$char = '';
		}
		return implode( '', $mailbox );
		
		//Regex equivalent of above. May be faster on newer versions of PHP with regex caching.
		//return preg_replace( '/[^a-z0-9!#$%&\'*+\/=?^_`{|}~\.-]+/i', '', $domain );
	}

	public function sanitize_domain( $domain ) {
		$domain = str_split( strtolower( $domain ) );
		foreach( $domain as &$char ) {
			if( !isset( $this->allowed_domain_chars[ $char ] ) )
				$char = '';
		}
		return implode( '', $domain );

		//Regex equivalent of above. May be faster on newer versions of PHP with regex caching.
		//return preg_replace( '/[^a-z0-9-.]+/i', '', $domain );
	}

	// String comparision functions
	public function find_closest_domain( $domain, $has_dot = true ) {
		$distance = false;
		$min_distance = 99;
		$closest = false;
		$threshold = $has_dot ? $this->settings->domain_threshold : $this->settings->second_level_threshold;
		$max_threshold = (int) floor( strlen( $domain ) / 2 );

		if( $threshold > $max_threshold )
			$threshold = $max_threshold;

		foreach ( $this->settings->domains as $canon ) {
			if( $domain === $canon )
				return $domain;
			
			// If tld is missing, only compare slds
			if( $has_dot )
				$distance = levenshtein( $domain, $canon );
			else
				$distance = levenshtein( $domain, substr( $canon, 0, strpos( $canon, '.' ) ) );

			if( $domain == 'yahoo.com' )
				var_dump( $distance );
			
			if( $distance < $min_distance ) {
				$min_distance = $distance;
				$closest = $canon;
			}
		}

		if( $min_distance <= $threshold && !empty( $closest ) )
			return $closest;
		
		return false;
	}

	public function find_closest_sld( $sld ) {
		return $this->find_closest( $sld, $this->settings->second_level_domains, $this->settings->second_level_threshold );
	}

	public function find_closest_tld( $tld ) {
		return $this->find_closest( $tld, $this->settings->top_level_domains, $this->settings->top_level_threshold );
	}

	public function find_closest( $needle, $haystack, $threshold ) {
		$distance = false;
		$min_distance = 99;
		$closest = false;
		$max_threshold = (int) floor( strlen( $needle ) / 2 );

		if( $threshold > $max_threshold )
			$threshold = $max_threshold;

		foreach ( $haystack as $canon ) {
			if( $needle === $canon )
				return $needle;
			
			$num_transpositions = $this->num_transpositions( $needle, $canon );
			if( $num_transpositions > 0 && $num_transpositions <= $threshold ) 
				return $canon;

			$distance = levenshtein( $needle, $canon );

			if( $distance < $min_distance ) {
				$min_distance = $distance;
				$closest = $canon;
			}
		}

		if( $min_distance <= $threshold && !empty( $closest ) )
			return $closest;
		
		return false;
	}

	public function find_one_character_off( $needle, $haystack ) {
		$length = strlen( $needle );
		foreach ( $haystack as $canon ) {
			if( $length + 1 === strlen( $canon ) && $needle === substr( $canon, 0, $length ) )
				return $canon;
		}

		return false;
	}

	public function num_transpositions( $actual, $desired ) {
		if( $desired === $actual )
			return 0;
	
		$dlength = strlen( $desired );
		if( $dlength !== strlen( $actual ) )
			return -1;
		
		$array1 = str_split( $desired );
		$array2 = str_split( $actual );

		$transpositions = 0;		
		for( $i = 0; $i<$dlength; $i++ ) {
			if( $array1[$i] === $array2[$i] )
				continue;

			if( $i+1 < $dlength && $array1[$i] === $array2[$i+1] && $array1[$i+1] === $array2[$i] ) {
				// Transpose characters
				$array2[$i] = $array1[$i];
				$array2[$i+1] = $array1[$i+1];
				$transpositions++;
			} else {
				return -1; // String is out of order more than flipped characters
			}
		}

		return $transpositions;
	}

	private function throwException($severity, $message, $file, $line) {
		if (!(error_reporting() & $severity)) {
			// This error code is not included in error_reporting
			return;
		}
		throw new ErrorException($message, 0, $severity, $file, $line);
  }
}
