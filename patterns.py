#!/usr/bin/python3
xxx = {
#	'1': {'name': 'General Secrets', 'regex': "(password|private|token|secret|key|authorization|bearer)"},
	'2': {'name': 'AWS s3', 'regex': "[a-z0-9.-]+\\.s3\\.amazonaws\\.com"},
	'3': {'name': 'AWS s3', 'regex': "[a-z0-9.-]+\\.s3-[a-z0-9-]\\.amazonaws\\.com"},
	'4': {'name': 'AWS s3', 'regex': "[a-z0-9.-]+\\.s3-website[.-](eu|ap|us|ca|sa|cn)"},
	'5': {'name': 'AWS s3', 'regex': "//s3\\.amazonaws\\.com/[a-z0-9._-]+"},
	'6': {'name': 'AWS s3', 'regex': "//s3-[a-z0-9-]+\\.amazonaws\\.com/[a-z0-9._-]+"},
	'7': {'name': 'Github', 'regex': "github.*['|\"][0-9a-zA-Z]{35,40}['|\"]"},
	'8': {'name': 'Google Key', 'regex': "AIza[0-9A-Za-z\\-\\_]{35}"},
	'9': {'name': 'AWS Keys', 'regex': "([^A-Z0-9]|^)(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}"},
	'10': {'name': 'Firebase', 'regex': "[a-z0-9.-]+\\.firebaseio\\.com"},
	'11': {'name': 'Firebase', 'regex': "[a-z0-9.-]+\\.firebaseapp\\.com"},
	'12': {'name': 'Firebase', 'regex': "[a-z0-9.-]+\\.appspot\\.com"},
	'13': {'name': 'Heroku Key', 'regex': "heroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}"},
	'14': {'name': 'Slack Token', 'regex': "(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})"},
	'15': {'name': 'Square Key', 'regex': "sq0atp-[0-9A-Za-z\\-\\_]{22}"},
	'16': {'name': 'Square Key', 'regex': "rsq0csp-[0-9A-Za-z\\-\\_]{43}"},
	'17': {'name': 'Stripe Key', 'regex': "sk_live_[0-9a-zA-Z]{24}"},
	'18': {'name': 'Stripe Key', 'regex': "rk_live_[0-9a-zA-Z]{24}"},
	'19': {'name': 'Twilio Key', 'regex': "SK[0-9a-fA-F]{32}"},
	'20': {'name': 'Google OAuth', 'regex': "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com"},
	'21': {'name': 'Google Token', 'regex': "ya29\\.[0-9A-Za-z\\-\\_]+"},
	'22': {'name': 'Mailgun Key', 'regex': "key-[0-9a-zA-Z]{32}"},
	'23': {'name': 'Paypal Token', 'regex': "[0-9a-f]{32}-us[0-9]{1,2}"},
	'24': {'name': 'Picatic Key', 'regex': "sk_live_[0-9a-z]{32}"},
	'25': {'name': 'Slack Webhook', 'regex': "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}"},
#	'26': {'name': 'Twitter OAuth', 'regex': "twitter.*['|\"][0-9a-zA-Z]{35,44}['|\"]"},
#	'27': {'name': 'Twitter Token', 'regex': "twitter.*[1-9][0-9]+-[0-9a-zA-Z]{40}"},
#	'28': {'name': 'Facebook OAuth', 'regex': "facebook.*['|\"][0-9a-f]{32}['|\"]"},
#	'29': {'name': 'Facebook Token', 'regex': "EAACEdEose0cBA[0-9A-Za-z]+"},
	'30': {'name': 'Mailchimp Key', 'regex': "[0-9a-f]{32}-us[0-9]{1,2}"},
	'31': {'name': 'Asymmetric Key', 'regex': "\\-\\-\\-\\-\\-BEGIN ((EC|PGP|DSA|RSA|OPENSSH) )?PRIVATE KEY( BLOCK)?\\-\\-\\-\\-\\-"},
	'32': {'name': 'Google Service Account', 'regex': "\"type\": \"service_account\""},
	'33': {'name': 'Debug Page', 'regex': "(Application-Trace|Routing Error|DEBUG\"? ?[=:] ?True|Caused by:|stack trace:|Microsoft .NET Framework|Traceback|[0-9]:in `|#!/us|WebApplicationException|java\\.lang\\.|phpinfo|swaggerUi|on line [0-9]|SQLSTATE)"},
	'34': {'name': 'Firebase', 'regex': "firebaseio.com"},
#	'35': {'name': 'Possible IMG Traversal', 'regex': "(=.*.jpg|=.*.jpeg|=.*.gif|=.*.png)"},
	'36': {'name': 'IP in source', 'regex': "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"},
#	'37': {'name': 'JWT', 'regex': "(jwt|jks|jwk|jku)"},
#	'38': {'name': 'Possible LFI', 'regex': "(file=|document=|folder=|root=|path=|pg=|style=|pdf=|template=|php_path=|doc=|page=|name=|cat=|dir=|action=|board=|date=|detail=|download=|prefix=|include=|inc=|locate=|show=|site=|type=|view=|content=|layout=|mod=|conf=)"},
	'39': {'name': 'PHP Error', 'regex': "(php warning|php error|fatal error|uncaught exception|include_path|undefined index|undefined variable|\\?php|<\\?[^x]|stack trace\\:|expects parameter [0-9]*|Debug Trace)"},
	'40': {'name': 'PHP Serialization', 'regex': "a:[0-9]+:{|O:[0-9]+:\"|s:[0-9]+:\""},
#	'41': {'name': 'Serialization', 'regex': "(pickle|yaml|serialize|marshal|objectinput)"},
#	'42': {'name': 'Possible SSTI', 'regex': "(template=|preview=|id=|view=|activity=|name=|content=|redirect=)"},
	'43': {'name': 'Possible Takeover', 'regex': "(There is no app configured at that hostname|NoSuchBucket|No Such Account|You're Almost There|a GitHub Pages site here|There's nothing here|project not found|Your CNAME settings|InvalidBucketName|PermanentRedirect|The specified bucket does not exist|Repository not found|Sorry, We Couldn't Find That Page|The feed has not been found.|The thing you were looking for is no longer here, or never was|Please renew your subscription|There isn't a Github Pages site here.|We could not find what you're looking for.|No settings were found for this company:|No such app|is not a registered InCloud YouTrack|Unrecognized domain|project not found|This UserVoice subdomain is currently available!|Do you want to register|Help Center Closed)"},
	'44': {'name': 'Upload Field', 'regex': "\u003cinput[^\u003e]+type=[\"']?file[\"']?"},
	'45': {'name': 'Sendgrid API Key', 'regex': '(SG\.[a-zA-Z0-9-_]{22}\.[a-zA-Z0-9_-]{43})'},
	'46': {'name': 'azure-storage', 'regex': "[a-zA-Z0-9_-]*\\.file.core.windows.net"},
	'47': {'name': 'error-mysql', 'regex': "(SQL syntax.*MySQL|Warning.*mysql_.*|MySqlException \\(0x|valid MySQL result|check the manual that corresponds to your (MySQL|MariaDB) server version|MySqlClient\\.|com\\.mysql\\.jdbc\\.exceptions)"},
	'48': {'name': 'error-postgresql', 'regex': "(PostgreSQL.*ERROR|Warning.*\\Wpg_.*|valid PostgreSQL result|Npgsql\\.|PG::SyntaxError:|org\\.postgresql\\.util\\.PSQLException|ERROR:\\s\\ssyntax error at or near)"},
	'49': {'name': 'error-mssql', 'regex': "(Driver.* SQL[\\-\\_\\ ]*Server|OLE DB.* SQL Server|\bSQL Server.*Driver|Warning.*mssql_.*|\bSQL Server.*[0-9a-fA-F]{8}|[\\s\\S]Exception.*\\WSystem\\.Data\\.SqlClient\\.|[\\s\\S]Exception.*\\WRoadhouse\\.Cms\\.|Microsoft SQL Native Client.*[0-9a-fA-F]{8})"},
	'50': {'name': 'error-msaccess', 'regex': "(Microsoft Access (\\d+ )?Driver|JET Database Engine|Access Database Engine|ODBC Microsoft Access)"},
	'51': {'name': 'error-oracle', 'regex': "(\\bORA-\\d{5}|Oracle error|Oracle.*Driver|Warning.*\\Woci_.*|Warning.*\\Wora_.*)"},
	'52': {'name': 'error-ibmdb2', 'regex': "(CLI Driver.*DB2|DB2 SQL error|\\bdb2_\\w+\\(|SQLSTATE.+SQLCODE)"},
	'53': {'name': 'error-informix', 'regex': "(Exception.*Informix)"},
	'54': {'name': 'error-firebird', 'regex': "(Dynamic SQL Error|Warning.*ibase_.*)"},
	'55': {'name': 'error-sqlite', 'regex': "(SQLite\\/JDBCDriver|SQLite.Exception|System.Data.SQLite.SQLiteException|Warning.*sqlite_.*|Warning.*SQLite3::|\\[SQLITE_ERROR\\])"},
	'56': {'name': 'error-sapdb', 'regex': "(SQL error.*POS([0-9]+).*|Warning.*maxdb.*)"},
	'57': {'name': 'error-sybase', 'regex': "(Warning.*sybase.*|Sybase message|Sybase.*Server message.*|SybSQLException|com\\.sybase\\.jdbc)"},
	'58': {'name': 'error-ingress', 'regex': "(Warning.*ingres_|Ingres SQLSTATE|Ingres\\W.*Driver)"},
	'59': {'name': 'error-frontbase', 'regex': "(Exception (condition )?\\d+. Transaction rollback.)"},
	'60': {'name': 'error-hsqldb', 'regex': "(org\\.hsqldb\\.jdbc|Unexpected end of command in statement \\[|Unexpected token.*in statement \\[)"},
	'61': {'name': 'error-mysql1', 'regex': "SQL syntax.*?MySQL"},
	'62': {'name': 'error-mysql2', 'regex': "Warning.*?mysqli?"},
	'63': {'name': 'error-mysql3', 'regex': "MySQLSyntaxErrorException"},
	'64': {'name': 'error-mysql4', 'regex': "valid MySQL result"},
	'65': {'name': 'error-mysql5', 'regex': "check the manual that (corresponds to|fits) your MySQL server version"},
	'66': {'name': 'error-mysql6', 'regex': "check the manual that (corresponds to|fits) your MariaDB server version"},
	'67': {'name': 'error-mysql7', 'regex': "check the manual that (corresponds to|fits) your Drizzle server version"},
	'68': {'name': 'error-mysql8', 'regex': "Unknown column '[^ ]+' in 'field list'"},
	'69': {'name': 'error-mysql9', 'regex': "com\\.mysql\\.jdbc"},
	'70': {'name': 'error-mysql10', 'regex': "Zend_Db_(Adapter|Statement)_Mysqli_Exception"},
	'71': {'name': 'error-mysql11', 'regex': "MySqlException"},
	'72': {'name': 'error-mysql12', 'regex': "Syntax error or access violation"},
	'73': {'name': 'error-psql1', 'regex': "PostgreSQL.*?ERROR"},
	'74': {'name': 'error-psql2', 'regex': "Warning.*?\\Wpg_"},
	'75': {'name': 'error-psql3', 'regex': "valid PostgreSQL result"},
	'76': {'name': 'error-psql4', 'regex': "Npgsql\\."},
	'77': {'name': 'error-psql5', 'regex': "PG::SyntaxError:"},
	'78': {'name': 'error-psql6', 'regex': "org\\.postgresql\\.util\\.PSQLException"},
	'79': {'name': 'error-psql7', 'regex': "ERROR:\\s\\ssyntax error at or near"},
	'80': {'name': 'error-psql8', 'regex': "ERROR: parser: parse error at or near"},
	'81': {'name': 'error-psql9', 'regex': "PostgreSQL query failed"},
	'82': {'name': 'error-psql10', 'regex': "org\\.postgresql\\.jdbc"},
	'83': {'name': 'error-psql11', 'regex': "PSQLException"},
	'84': {'name': 'error-mssql1', 'regex': "Driver.*? SQL[\\-\\_\\ ]*Server"},
	'85': {'name': 'error-mssql2', 'regex': "OLE DB.*? SQL Server"},
	'86': {'name': 'error-mssql3', 'regex': "\bSQL Server[^&lt;&quot;]+Driver"},
	'87': {'name': 'error-mssql4', 'regex': "Warning.*?\\W(mssql|sqlsrv)_"},
	'88': {'name': 'error-mssql5', 'regex': "\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}"},
	'89': {'name': 'error-mssql6', 'regex': "System\\.Data\\.SqlClient\\.SqlException"},
	'90': {'name': 'error-mssql7', 'regex': "(?s)Exception.*?\bRoadhouse\\.Cms\\."},
	'91': {'name': 'error-mssql8', 'regex': "Microsoft SQL Native Client error '[0-9a-fA-F]{8}"},
	'92': {'name': 'error-mssql9', 'regex': "\\[SQL Server\\]"},
	'93': {'name': 'error-mssql10', 'regex': "ODBC SQL Server Driver"},
	'94': {'name': 'error-mssql11', 'regex': "ODBC Driver \\d+ for SQL Server"},
	'95': {'name': 'error-mssql12', 'regex': "SQLServer JDBC Driver"},
	'96': {'name': 'error-mssql13', 'regex': "com\\.jnetdirect\\.jsql"},
	'97': {'name': 'error-mssql14', 'regex': "macromedia\\.jdbc\\.sqlserver"},
	'98': {'name': 'error-mssql15', 'regex': "Zend_Db_(Adapter|Statement)_Sqlsrv_Exception"},
	'99': {'name': 'error-mssql16', 'regex': "com\\.microsoft\\.sqlserver\\.jdbc"},
	'100': {'name': 'error-mssql18', 'regex': "SQL(Srv|Server)Exception"}
}
