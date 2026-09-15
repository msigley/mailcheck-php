<?php
include 'mailcheck.php';

$MailCheck = new MailCheck();

$typo_tests = array(
	//Sanitation tests
	'test@#gmail.com',
	'test@gmail.com#',
	' test@yahoo.com ',
	'test@<gmail>.com',
	'test@@aol.com',
	//Suggestion tests
	'test@gmail',
	'test@yahoo',
	'test@apple',
	'test@aol',
	'test@me',
	'test@hotmail',
	'test@gooooogle.com',
	'test@yahoo.co',
	'test@yahoo.co.',
	'test@yahoo.co.u',
	'test@gmailc.om',
	'test@emaildomain.co',
	'test@gmail.con',
	'test@gnail.con',
	'test@GNAIL.con',
	'test@comcast.nry',
	'test@homail.con',
	'test@hotmail.co',
	'test@yajoo.com',
	'test@randomsmallcompany.cmo',
	'test@con-artists.con',
	'test@yahooo.cmo',
	'test@yahoo.co.uk',
	'test@gmx.fr',
	'test@gm',
	'test@gma',
	'test@gmai',
	'test@gmail.fr',
	'test@yahoo.fr',
	'test@outlook.fr',
	'test@hotmail.fr',
	'test@9.fr',
	'test@nordnet.fr',
	'test@example1.com',
	'test@gmail.tv',
	// Validation tests
	'test@gmail.com',
	'test@yahoo.com',
	'test@aol.com',
	'test@electricquilt.com',
	'test@thereisnowaythisdomainexists.com',
	// Role tests
	'1223123@gmail.com',
	'hr@gmail.com',
	'webmaster@yahoo.com',
	'sales@hotmail.com'
);

if( isset( $_GET['html'] ) ) :
?>
<html>
<body>
	<h1>MailCheck Tests</h1>
	<h2>Typo Suggestions</h2>
	<table>
		<thead>
			<tr>
				<th>Typo</th>
				<th>Suggestion</th>
				<th>Valid</th>
				<th>DNS Valid</th>
				<th>Role Based</th>
			</tr>
		</thead>
		<tbody>
			<?php foreach( $typo_tests as $typo ) : ?>
				<tr>
					<td><?php echo htmlentities( $typo ); ?></td>
					<td><?php echo htmlentities( $MailCheck->suggest( $typo ) ); ?></td>
					<td><?php echo $MailCheck->validate_email( $typo ) ? 'true' : 'false'; ?></td>
					<td><?php echo $MailCheck->validate_email( $typo, true ) ? 'true' : 'false'; ?></td>
					<td><?php echo $MailCheck->is_role_based_email( $typo ) ? 'true' : 'false'; ?></td>
				</tr>
			<?php endforeach; ?>
		</tbody>
	</table>
</body>
</html>
<?php 
else:
echo str_pad( "Typo", 40, " " ).str_pad( "Suggestion", 40, " " ).str_pad( "Valid", 8, " " ).str_pad( "DNS Valid", 12, " " ).str_pad( "Role Based", 13, " " )."\n";
foreach( $typo_tests as $typo ) :
    echo str_pad( $typo, 40, " " );
    echo str_pad( $MailCheck->suggest( $typo ), 40, " " );
    echo str_pad( $MailCheck->validate_email( $typo ) ? 'true' : 'false', 8, " " );
    echo str_pad( $MailCheck->validate_email( $typo, true ) ? 'true' : 'false', 12, " " );
	echo str_pad( $MailCheck->is_role_based_email( $typo ) ? 'true' : 'false', 13, " " );
    echo "\n";
endforeach;
endif;