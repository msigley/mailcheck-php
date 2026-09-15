<?php
require_once 'mailcheck.php';
$mailcheck = new MailCheck();

@mkdir( 'VALIDATED', 0655 );
$csv_files = glob( __DIR__ . DIRECTORY_SEPARATOR . '*.csv');
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
    $valid_fp = fopen( __DIR__ . DIRECTORY_SEPARATOR . $valid_csv_file, 'w+' );
    fputcsv( $valid_fp, $headers );
    $corrected_csv_file = 'VALIDATED/' . $csv_file_info['filename'] . '_CORRECTED' . '.' . $csv_file_info['extension'];
    $corrected_fp = fopen( __DIR__ . DIRECTORY_SEPARATOR . $corrected_csv_file, 'w+' );
    fputcsv( $corrected_fp, array_merge( $headers, array( 'CORRECTED FROM' ) ) );
    $invalid_csv_file = 'VALIDATED/' . $csv_file_info['filename'] . '_INVALID' . '.' . $csv_file_info['extension'];
    $invalid_fp = fopen( __DIR__ . DIRECTORY_SEPARATOR . $invalid_csv_file, 'w+' );
    fputcsv( $invalid_fp, array_merge( $headers, array( 'INVALID REASON' ) ) );
    $counts = array( 'processed' => 0, 'valid' => 0, 'corrected' => 0, 'invalid' => 0 );
    $corrected = array();
    while( ( $line = fgetcsv( $fp ) ) !== false ) {
        $counts['processed']++;
        $line[$email_index] = trim( $line[$email_index] );
        $valid = $mailcheck->validate_email( $line[$email_index], true );
        $role_based = $mailcheck->is_role_based_email( $line[$email_index] );
        if( $valid && !$role_based ) {
            fputcsv( $valid_fp, $line );
            $counts['valid']++;
        } elseif( $suggested_email = $mailcheck->suggest( $line[$email_index] ) ) {
            if( $mailcheck->validate_email( $suggested_email, true ) && !$mailcheck->is_role_based_email( $line[$email_index] ) ) {
                $line[] = $line[$email_index];
                $line[$email_index] = $suggested_email;
                fputcsv( $corrected_fp, $line );
                $counts['corrected']++;
            }
        } else {
            if( $role_based )
                $line[] = 'ROLE BASED EMAIL';
            else
                $line[] = 'INVALID EMAIL';
            fputcsv( $invalid_fp, $line );
            $counts['invalid']++;
        }

        echo "Processed: {$counts['processed']} Valid: {$counts['valid']} Corrected: {$counts['corrected']} Invalid {$counts['invalid']}                            \r";
    }
    fclose( $valid_fp );
    fclose( $corrected_fp );
    fclose( $invalid_fp );
    echo "Processed: {$counts['processed']} Valid: {$counts['valid']} Corrected: {$counts['corrected']} Invalid {$counts['invalid']}\n";
}