" Vim syntax file
" " Language:         ITM 6 log syntax 
" " Maintainer:       David Washington (washingd@us.ibm.com)
" " Latest Revision:  2015-06-25

syntax clear
syntax case match

" ITM Config Section
"
syn keyword itm_config KBB_RAS1 BSS1_GetEnv KDC_DEBUG KDE_DEBUG KBBRA_ChangeLogging
syn match itm_KD_DEBUG /\sKD.*_DEBUG=/
syn match itm_cmslist /\"BSS1_GetEnv\".*\sCT_CMSLIST=.*\n/
syn match itm_driver /\sDriver:\stms/
syn match itm_port /KDEBP_AssignPort\".*\n/
" syn keyword itm_port KDEBP_AssignPort
syn match itm_nofile /\sNofile\sLimit:\s/
syn match itm_tems_connect_1 /\Successfully\sconnected\sto\sCMS\s.*\n/
syn match itm_tems_connect_2 /\Successfully\sconnected\sto\sTEMS\s.*\n/
syn match wpa_tdw_success /\sConnection\swith\sDatasource\s.*successful/
syn match itm_sth_file /sendDataToProxy")\sSending\s\d/
syn match itm_agent_wpa /\sSetting\snew\swarehouse\slocation\sto/
syn match itm_err_uid_pwd /User\sID\sor\spassword\sis\sinvalid/
syn match tems_locks /.*\sCTIRA_Recursive_lock\sobjects\sfor\sclass\sRequestImp/
syn match tems_sda /\"BSS1_GetEnv\")\sKMS_SDA=.*/
syn match tems_kms_sec /\"BSS1_GetEnv\")\sKMS_SECURITY_COMPATIBILITY_MODE=.*/
syn match tems_eif_dest /\sEIF\sevents\sto\sdestination\s<.*>/
syn match itm_ctira_hostname /\sCTIRA_HOSTNAME=.*\n/
syn match itm_ctira_system_name /\sCTIRA_SYSTEM_NAME=.*\n/
syn match itm_kdeb_interface /\sKDEB_INTERFACELIST=/


" Common Error Section
syn match itm_err_cms_connect /\sUnable\sto\sfind\srunning.*\n/
syn match itm_errors /\sCaused\sby/
syn match itm_err_password /\sPassword\sinvalid/
syn keyword itm_gskit_err01 CryptoFailedException
syn match itm_gskit_err02 /\sGSK_ERROR_/
syn match itm_err_db_connect /\"Database\sconnection\sfailed\"/
syn match itm_err_connect_fail /\sConnection\sfailure:\s/
syn match itm_err_connect_refuse /\sConnection\srefused/
syn match itm_err_connect_lost /\sConnection\slost/
syn match itm_err_bad_return /\sBad\sreturn\scode\s/
syn match itm_err_failed_export /\sfailed\sin\screateRouteRequest/
syn match itm_err_export_66 /\sstatus\s=\s66,\sfor\sobject.*\n/

" TEMS Section
syn match tems_err_sitfilter /Filter\sobject\stoo\sbig\s.*/
syn match tems_node_failed /Validation\sfor\snode\sfailed/
syn match tems_err_rrn /ERROR:\sfor\sRRN\s.*/

" TEPS Section
syn match teps_kfw_interfaces  /\sKFW_INTERFACES=\".*\"/
syn match teps_online  /\sWaiting\sfor\srequests/
syn match teps_login /\sKFW1100I\s/
syn match teps_err_loginmapping /No\svalid\suser\smapping\s/
syn match teps_err_ipaddr /\sIP\sADDR\sCHANGE\s/
syn match teps_ior /\sWriting\sIOR\sfile.*\n/
syn match teps_err_db2_errcode /\sSQL\d\+N\s/
syn match teps_err_db2_SQLC /\sSQL\d\+C\s/
syn match teps_err_openrequest /SQL1_OpenRequest\sfailed\s/
syn match teps_err_closerequest /SQL1_CloseRequest\sfailed\src=/
syn match teps_err_createrequest /SQL1_CreateRequest\sfailed/
syn match teps_err_fatal_IHS /\sProblem\slocating\sIHS\scontrol\scommand/
syn match teps_tdw_connection /\sNo\sWarehouse\sfound\sfor.*/
syn match teps_shutdown /\sShutdown\sinitiated/
syn match teps_CANDLEHOME /=\"|CANDLE_HOME|/
syn match teps_CANDLEHOME_a /using\s|CANDLE_HOME|/
syn match teps_aix_IV77462 /\sConversation\stimeout:\s.*1C010008:00000000,/
syn match teps_describeDataSource /::describeDataSource.*/

" WPA Section
syn match wpa_online /\sTivoli\sExport\sServer\sReady.*\n/
syn match wpa_user /\sKHD_WAREHOUSE_USER=.*\n/
syn match wpa_jdbcdriver /\sKHD_JDBCDRIVER=.*\n/
syn match wpa_jdbcurl /\sKHD_JDBCURL=.*\n/
syn match wpa_jars /\sKHD_WAREHOUSE_JARS=.*\n/
syn match wpa_tems_list /\sKHD_WAREHOUSE_TEMS_LIST=.*\n/
syn keyword wpa_errors CTX_JDBCError CTX_Critical SqlDataException KHDBatchFailureException CTX_ConnectionFailed CTX_ServerTimeout CTX_InitializationFailed CTX_ODBCError CTX_WarehouseProxyNotRegistered CTX_RPCError
syn keyword wpa_err_fatal CTX_Fatal CTX_InitJVMError 
syn match wpa_err_reject /\sREJECTED:\sThe\sexport\sfor\sthe\soriginnode\s/
syn match wpa_err_testdb /\stestDatabaseConnection\sfailed/

" SY Section
syn match sy_teps /CNP\sserver\s.*\n/
syn match sy_jdbc_driver /\sLoading\sdriver\s/
syn match sy_jdbc_url /\sAttempting\sconnection\swith\sURL\s.*\n/
syn match sy_jars /\swarehouseJars/
syn match sy_database /\sConnecting\sto\sthe\swarehouse\sdatabase\s.*\n/
syn match sy_tep_connect /\sto\sthe\sTEP\sServer\sat\s.*\n/
syn match sy_schedule /\sScheduled time\s.*\n/
syn match sy_complete /.*\sfor\sall\sproducts\n/
syn match sy_tot_read /\sTotal\srows\sread.*\n/
syn match sy_tot_prune /\sTotal\srows\spruned.*\n/
syn match sy_attempted /\sTables\sattempted\s:.*\n/
syn match sy_err_tep_connect_crit /\sTEP\sServer\sfailed/
syn match sy_err_sqlexception /SqlException/
syn match sy_shutdown /\sshutdown\scommand\sreceived/


" Common Agent Errors
"
syn match khd_hist_size /\sTotal\ssize\sof\shistorical\sfiles.*\sexceeded\sthe\smaximum\sof/

" DB2 Errors
syn match db2_err_SQL1032N  /\sNo\sstart\sdatabase\smanager\scommand\s/
syn match db2_err_sql /\sDB2\sSQL\sError/
syn match db2_err_sql_N /IBM.*\sSQL\d\+N\s.*/
syn match db2_err_codepage_FATAL /\sDatabase\sclient\sencoding\sis\snot\sUTF8/
"

" Oracle Errors
syn match oracle_error_colon  /\sORA-\d\+\:/
syn match oracle_error_space  /\sORA-\d\+\s/


" Highlight  Section
"
"
"
" ITM Config & Informational Section 
hi itm_nofile ctermbg=green ctermfg=black
hi itm_config ctermbg=green ctermfg=black
hi itm_driver ctermbg=green ctermfg=black
hi itm_port ctermbg=green ctermfg=black
hi itm_KD_DEBUG ctermbg=green ctermfg=black
hi itm_cmslist ctermbg=green ctermfg=black
hi itm_tems_connect_1 ctermbg=DarkBlue ctermfg=white
hi itm_tems_connect_2 ctermbg=DarkBlue ctermfg=white
hi itm_sth_file ctermbg=DarkBlue ctermfg=white
hi itm_agent_wpa ctermbg=DarkBlue ctermfg=white
hi itm_ctira_hostname ctermbg=DarkBlue ctermfg=white
hi itm_ctira_system_name ctermbg=DarkBlue ctermfg=white
hi itm_kdeb_interface ctermbg=DarkBlue ctermfg=white
hi wpa_tdw_success ctermbg=DarkBlue ctermfg=white
hi tems_sda ctermbg=green ctermfg=black
hi tems_kms_sec ctermbg=green ctermfg=black
hi tems_eif_dest ctermbg=green ctermfg=black
hi teps_shutdown ctermbg=green ctermfg=black
hi sy_shutdown ctermbg=green ctermfg=black

" Warning Errors
hi itm_err_export_66 ctermbg=yellow ctermfg=black
hi itm_err_uid_pwd ctermbg=yellow ctermfg=black
hi itm_err_connect_fail ctermbg=yellow ctermfg=black
hi itm_err_connect_refuse ctermbg=yellow ctermfg=black
hi itm_err_connect_lost ctermbg=yellow ctermfg=black
hi itm_err_bad_return ctermbg=yellow ctermfg=black
hi teps_err_ipaddr ctermbg=yellow  ctermfg=black
hi teps_err_createrequest ctermbg=yellow ctermfg=black
hi teps_err_openrequest ctermbg=yellow ctermfg=black
hi teps_err_loginmapping ctermbg=yellow ctermfg=black
hi teps_aix_IV77462 ctermbg=yellow ctermfg=black
hi tems_err_sitfilter ctermbg=yellow ctermfg=black

" Critical Errors
hi khd_hist_size ctermbg=red ctermfg=white
hi itm_gskit_err01 ctermbg=red ctermfg=white
hi itm_gskit_err02 ctermbg=red ctermfg=white
hi itm_errors ctermbg=red ctermfg=white
hi itm_err_password ctermbg=red ctermfg=white
hi itm_err_failed_export ctermbg=red ctermfg=white
hi sy_err_tep_connect_crit ctermbg=red ctermfg=white

" Fatal Errors
hi tems_locks ctermbg=92 ctermfg=white
hi itm_err_cms_connect ctermbg=92 ctermfg=white
hi itm_err_db_connect ctermbg=92 ctermfg=white
hi wpa_err_fatal ctermbg=92 ctermfg=white
hi wpa_err_testdb ctermbg=92 ctermfg=white
hi teps_err_fatal_IHS ctermbg=92 ctermfg=white
hi db2_err_SQL1032N ctermbg=92 ctermfg=white
hi db2_err_codepage_FATAL ctermbg=92 ctermfg=white
hi teps_CANDLEHOME ctermbg=92 ctermfg=white
hi teps_CANDLEHOME_a ctermbg=92 ctermfg=white

" TEMS Highlight Section
hi tems_node_failed ctermbg=yellow ctermfg=black
hi tems_err_rrn ctermbg=red ctermfg=white

" TEPS Section
hi teps_online ctermbg=DarkBlue ctermfg=white
hi teps_login ctermbg=DarkBlue ctermfg=white
hi teps_kfw_interfaces ctermbg=green ctermfg=black
hi teps_ior ctermbg=green ctermfg=black
hi teps_err_closerequest ctermbg=red ctermfg=white
hi teps_tdw_connection ctermbg=red ctermfg=white
hi teps_describeDataSource ctermbg=green ctermfg=black

" WPA Section
hi wpa_online ctermbg=DarkBlue ctermfg=white
hi wpa_user ctermbg=green ctermfg=black
hi wpa_jdbcdriver ctermbg=green ctermfg=black
hi wpa_jdbcurl ctermbg=green ctermfg=black
hi wpa_jars ctermbg=green ctermfg=black
hi wpa_tems_list ctermbg=yellow ctermfg=black
hi wpa_errors ctermbg=red ctermfg=white
hi wpa_err_reject ctermbg=red ctermfg=white

" SY Section
hi sy_teps ctermbg=DarkBlue ctermfg=white
hi sy_jdbc_driver ctermbg=DarkBlue ctermfg=white
hi sy_jdbc_url ctermbg=DarkBlue ctermfg=white
hi sy_jars ctermbg=DarkBlue ctermfg=white
hi sy_database ctermbg=DarkBlue ctermfg=white
hi sy_tep_connect ctermbg=DarkBlue ctermfg=white
hi sy_schedule ctermbg=DarkBlue ctermfg=white
hi sy_complete ctermbg=DarkBlue ctermfg=white
hi sy_tot_read ctermbg=DarkBlue ctermfg=white
hi sy_tot_prune ctermbg=DarkBlue ctermfg=white
hi sy_attempted ctermbg=DarkBlue ctermfg=white

" DB2 Errors
hi db2_err_sql ctermbg=red ctermfg=white
hi teps_err_db2_errorcode ctermbg=red  ctermfg=white
hi teps_err_db2_SQLC ctermbg=red ctermfg=white
hi db2_err_sql_N ctermbg=red ctermfg=white
hi sy_err_sqlexception ctermbg=red ctermfg=white
"
" Oracle Errors
hi oracle_error_colon ctermbg=red ctermfg=white
hi oracle_error_space ctermbg=red ctermfg=white
"
"







