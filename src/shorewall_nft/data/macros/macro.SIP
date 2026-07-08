#
# Shorewall -- /usr/share/shorewall/macro.SIP
#
# This macro handles SIP traffic.
#
###############################################################################
#ACTION	SOURCE	DEST	PROTO	DPORT	SPORT	ORIGDEST	RATE	USER

?if ( __CT_TARGET && ! $AUTOHELPERS && __SIP_HELPER  )
 PARAM	-	-	udp	5060 { helper=sip }
?else
 PARAM	-	-	udp	5060
?endif
