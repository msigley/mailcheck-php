<?php
// File to be run from the command line to validate and correct CSVs of emails.
require_once 'mailcheck.php';
$mailcheck = new MailCheck();

@mkdir( 'VALIDATED', 0655 );
$csv_files = glob('*.csv');
foreach( $csv_files as $csv_file ) {
    echo "$csv_file\n";
    $fp = fopen( $csv_file, 'r' );
    $headers = fgetcsv( $fp );
    $email_index = false;
    foreach( $headers as $index => $name ) {
        if( strtolower( substr( $name, 0, 5 ) ) === 'email' ) {
            $email_index = $index;
            break;
        }
    }

    if( $email_index === false ) {
        echo "Unable to determine email column.\n";
        continue;
    }

    $csv_file_info = pathinfo( $csv_file );
    $valid_csv_file = 'VALIDATED/' . $csv_file_info['filename'] . '_VALID' . '.' . $csv_file_info['extension'];
    $valid_fp = fopen( $valid_csv_file, 'w+' );
    $counts = array( 'processed' => 0, 'valid' => 0, 'corrected' => 0, 'invalid' => 0 );
    $corrected = array();
    while( ( $line = fgetcsv( $fp ) ) !== false ) {
        $counts['processed']++;
        $output = false;
        if( $mailcheck->validate_email( $line[$email_index], true ) ) {
            $output = true;
            $counts['valid']++;
        } elseif( $suggested_email = $mailcheck->suggest( $line[$email_index] ) ) {
            if( $mailcheck->validate_email( $suggested_email, true ) ) {
                $corrected[$line[$email_index]] = $suggested_email;
                $line[$email_index] = $suggested_email;
                $output = true;
                $counts['corrected']++;
            }
        }

        if( $output )
            fputcsv( $valid_fp, $line );
        else
            $counts['invalid']++;

        echo "Processed: {$counts['processed']} Valid: {$counts['valid']} Corrected: {$counts['corrected']} Invalid {$counts['invalid']}                            \r";
    }
    fclose( $valid_fp );
    echo "Processed: {$counts['processed']} Valid: {$counts['valid']} Corrected: {$counts['corrected']} Invalid {$counts['invalid']}\n";
    foreach( $corrected as $og => $new ) {
        echo "$og corrected to $new\n";
    }
}
