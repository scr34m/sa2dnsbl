CREATE DATABASE IF NOT EXISTS sa2dnsbl;
CREATE TABLE IF NOT EXISTS sa2dnsbl.sa2dnsbl (
   `ip` varbinary(16) NOT NULL default 0,
   `ham_hits` int(16) default NULL,
   `spam_hits` int(16) default NULL,
   `reputation` int(8) NOT NULL default 50,
   `lastchange` timestamp NOT NULL default CURRENT_TIMESTAMP,
   PRIMARY KEY  (`ip`)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS sa2dnsbl_log (
   `id` int(11) NOT NULL AUTO_INCREMENT,
   `server_ip` varbinary(16) NOT NULL,
   `ip` varbinary(16) NOT NULL default 0,
   `score` decimal(5,2) default NULL,
   `time` timestamp NOT NULL default CURRENT_TIMESTAMP,
   `subject` varchar(255) default NULL,
   PRIMARY KEY  (`id`)
) ENGINE=InnoDB;
GRANT select, insert, update, delete ON sa2dnsbl.* TO 'sa2dnsbl'@'%your.domain.tld' IDENTIFIED BY 'secret';

