
#		AWS API
#	Tommy Freethy - February 2020
#
# AWS API documentation can be found here: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Welcome.html
#
# This file contains a couple of examples working with AWS' API to manipulate an
# AWS EC2 instance. The examples include 2 GET requests, along
# with the elaborate signing process for each.
#
# One request retrieves the list of network ACLs and the other request creates
# an entry in the network ACLs.
#
# The purpose of this was to black list any IP addresses abusing my web server
# running in an EC2 instance.


package require http
package require tls
package require sha256

namespace eval aws_api {
	variable _access_key "********************"
	variable _secret_key "****************************************"
	
	proc main {} {
		http::register https 443 [list ::tls::socket -tls1 1]
		
		aws_request_post
		
		http::unregister https;
	}
	
	# This is an example of a GET request to AWS' API. Throughout the code I have
	# indicated each step in the signing process laid out in the API documentation.
	proc aws_request_get {} {
		variable _secret_key
		variable _access_key
		
		set RequestBody ""
		set Region "us-east-1"
		set Service "ec2"
		set Host "${Service}.amazonaws.com"
		
		set AMZdate [clock format [clock seconds] -format "%Y%m%dT%H%M%SZ" -timezone :UTC]
		set DateStamp [clock format [clock seconds] -format "%Y%m%d" -timezone :UTC]
		
		# --------- TASK 1: CREATE A CANONICAL REQUEST ---------
		
		# Step 1 - Define verb (GET, POST, etc.)
		set Method "GET"
		
		# Step 2 - Create canonical uri, "/" if no path
		set CanonicalURI "/"
		
		# Step 3 - Create canonical query string
		set Query(Action) "DescribeNetworkAcls"
		set Query(Version) "2016-11-15"
		
		set CanonicalQueryString ""
		foreach Index [lsort [array names Query]] {
			if {$CanonicalQueryString ne ""} {
				append CanonicalQueryString "&"
			}
			append CanonicalQueryString [::http::formatQuery $Index $Query($Index)]
		}
		puts "CanonicalQueryString=\n$CanonicalQueryString\n------------------------------"
		
		# Step 4&5 - Create canonical headers and signed headers
		set Headers(host) $Host
		set Headers(x-amz-date) $AMZdate
		
		set CanonicalHeaders ""
		set SignedHeaders ""
		foreach Header [lsort [array names Headers]] {
			append CanonicalHeaders "${Header}:$Headers($Header)\n"
			append SignedHeaders "${Header};"
		}
		set SignedHeaders [string range $SignedHeaders 0 end-1]
		
		# Step 6 - Create hash of the request body content. "" for GET requests
		# Step 7 - Combine everything to create the canonical request
		set CanonicalRequest ""
		append CanonicalRequest "$Method\n"
		append CanonicalRequest "$CanonicalURI\n"
		append CanonicalRequest "$CanonicalQueryString\n"
		append CanonicalRequest "$CanonicalHeaders\n"
		append CanonicalRequest "$SignedHeaders\n" 
		append CanonicalRequest [::sha2::sha256 $RequestBody]
		puts "$CanonicalRequest\n------------------------------"
		
		# --------- TASK 2: CREATE THE STRING tO SIGN ---------
		
		set CredentialScope "$DateStamp/$Region/$Service/aws4_request"
		
		set StringToSign "AWS4-HMAC-SHA256\n"
		append StringToSign "$AMZdate\n"
		append StringToSign "$CredentialScope\n"
		append StringToSign [::sha2::sha256 $CanonicalRequest]
		puts "$StringToSign\n------------------------------"
		
		# --------- TASK 3: CALCULATE THE SIGNATURE ---------
		
		# Create the signing key
		set Kdate [::sha2::hmac -bin -key "AWS4$_secret_key" $DateStamp]
		set Kregion [::sha2::hmac -bin -key "$Kdate" $Region]
		set Kservice [::sha2::hmac -bin -key "$Kregion" $Service]
		set Ksigning [::sha2::hmac -bin -key "$Kservice" "aws4_request"]
		puts "HexSigningKey=[binary encode hex $Ksigning]\n------------------------------"
		
		# Sign the StringToSign with the signing key we just generated
		set Signature [::sha2::hmac $Ksigning $StringToSign]
		puts "Signature=$Signature\n------------------------------"
		
		# --------- TASK 4: ADD SIGNING INFO TO REQUEST ---------
		
		set AuthHeader "AWS4-HMAC-SHA256 Credential=${_access_key}/${CredentialScope},SignedHeaders=$SignedHeaders,Signature=$Signature"
		puts "AuthHeader=$AuthHeader\n------------------------------"
		set Headers(Authorization) $AuthHeader
		
		# --------- REQUEST TO AWS--------- 
		
		aws_request "https://${Host}/?$CanonicalQueryString" [array get Headers]
	}
	
	# Here is another example of a GET request to AWS' API. I have not gone through and
	# commented like I have with the other example. The process is very similar, the 
	# key difference is that most headers appear in the query string instead.
	proc aws_request_post {} {
		variable _secret_key
		variable _access_key
		
		set RequestBody ""
		set Region "us-east-1"
		set Service "ec2"
		set Host "${Service}.amazonaws.com"
		
		set AMZdate [clock format [clock seconds] -format "%Y%m%dT%H%M%SZ" -timezone :UTC]
		set DateStamp [clock format [clock seconds] -format "%Y%m%d" -timezone :UTC]
		
		set CanonicalHeaders ""
		append CanonicalHeaders "host:$Host\n"
		
		set SignedHeaders "host"
		
		set CredentialScope "$DateStamp/$Region/$Service/aws4_request"
		
		set Method "GET"
		set CanonicalURI "/"
		
		set CanonicalQueryString [::http::formatQuery \
			Action "CreateNetworkAclEntry" \
			CidrBlock "44.224.22.196/32" \
			Egress "false" \
			NetworkAclId "acl-********" \
			PortRange.From "443" \
			PortRange.To "443" \
			Protocol "6" \
			RuleAction "deny" \
			RuleNumber "201" \
			Version "2016-11-15" \
			X-Amz-Algorithm "AWS4-HMAC-SHA256" \
			X-Amz-Credential "${_access_key}/${CredentialScope}" \
			X-Amz-Date $AMZdate \
			X-Amz-Expires "30" \
			X-Amz-SignedHeaders $SignedHeaders \
		]
		puts "CanonicalQueryString=\n$CanonicalQueryString\n------------------------------"
		
		
		set CanonicalRequest ""
		append CanonicalRequest "$Method\n"
		append CanonicalRequest "$CanonicalURI\n"
		append CanonicalRequest "$CanonicalQueryString\n"
		append CanonicalRequest "$CanonicalHeaders\n"
		append CanonicalRequest "$SignedHeaders\n" 
		append CanonicalRequest [::sha2::sha256 $RequestBody]
		puts "$CanonicalRequest\n------------------------------"
		
		
		set StringToSign "AWS4-HMAC-SHA256\n"
		append StringToSign "$AMZdate\n"
		append StringToSign "$CredentialScope\n"
		append StringToSign [::sha2::sha256 $CanonicalRequest]
		puts "$StringToSign\n------------------------------"
		
		set Kdate [::sha2::hmac -bin -key "AWS4$_secret_key" $DateStamp]
		set Kregion [::sha2::hmac -bin -key "$Kdate" $Region]
		set Kservice [::sha2::hmac -bin -key "$Kregion" $Service]
		set Ksigning [::sha2::hmac -bin -key "$Kservice" "aws4_request"]
		set HexSigningKey [binary encode hex $Ksigning]
		puts "HexSigningKey=$HexSigningKey\n------------------------------"
		
		set Signature [::sha2::hmac $Ksigning $StringToSign]
		puts "Signature=$Signature\n------------------------------"
		
		
		set AuthHeader "AWS4-HMAC-SHA256 Credential=${_access_key}/${CredentialScope},SignedHeaders=$SignedHeaders,Signature=$Signature"
		puts "AuthHeader=$AuthHeader\n------------------------------"
		
		append CanonicalQueryString "&X-Amz-Signature=$Signature"
		
		aws_request "https://${Host}/?$CanonicalQueryString"
	}
	
	# This procedure sends the actual HTTP request to AWS
	proc aws_request {Url {Headers {}}} {
		puts "aws_request...sending request to: $Url"
		if {[catch {
			if {$Headers ne ""} {
				set Token [::http::geturl $Url \
					-headers $Headers \
					-timeout 10000 \
				]
			} else {
				set Token [::http::geturl $Url \
					-timeout 10000 \
				]
			}
		} Error]} {
			puts "aws_request...Something went wrong on $Url: $Error"
			return "";
		}
		
		if {[http::status $Token] eq "timeout"} {
			puts "aws_request...timeout on $Url"
			http::cleanup $Token
		}
		
		set Result [http::data $Token]
		# puts "aws_request...Result=$Result"
		
		if {[http::ncode $Token] ne 200} {
			puts "aws_request...code not 200 on $Url"
			foreach {Name Value} [http::meta $Token] {
				puts "aws_request...$Name=$Value"
			}
		}
		
		http::cleanup $Token
		return $Result
	}
}


aws_api::main


