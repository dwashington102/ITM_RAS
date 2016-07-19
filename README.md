Running the Perl scripts against the ITM RAS logs  will extract configuration  information along with dknown errors.

In order to run the Perl scripts on MS-Windows use this procedure
> Download ZIP file containing the scripts
> Extract the scripts to specific directory.  This example will use C:\IBM\ITMRAS
> Add the C:\IBM\ITMRAS to the environment PATH
ex:  set PATH=%PATH%;C:\IBM\ITMRAS

Call the scripts using:
c:\ perl C:\IBM\ITMRAS\reviewras cq





While loading the raslog.vim in vim and viewing a RAS log will highlight configuration information and errors within the RAS log.

For instructions on automatically loading the raslog.vim syntax file,  view the header
information in the raslog.vim file.

Screenshot of ITM RAS log opened in VIM  using the raslog.vim syntax file.

![alt text](screenshot.png  "ITM RAS LOG with BSS1 ENV highlighted")
