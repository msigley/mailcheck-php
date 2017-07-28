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
	'test@thereisnowaythisdomainexists.com'
);
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
			</tr>
		</thead>
		<tbody>
			<?php foreach( $typo_tests as $typo ) : ?>
				<tr>
					<td><?php echo htmlentities( $typo ); ?></td>
					<td><?php echo htmlentities( $MailCheck->suggest( $typo ) ); ?></td>
					<td><?php echo $MailCheck->validate_email( $typo ) ? 'true' : 'false'; ?></td>
					<td><?php echo $MailCheck->validate_email( $typo, true ) ? 'true' : 'false'; ?></td>
				</tr>
			<?php endforeach; ?>
		</tbody>
	</table>
</body>
</html>
