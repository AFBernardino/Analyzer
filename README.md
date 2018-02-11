# Analyzer
Program that search php vulnerabilities in slices.  

Used to understand and pratice some concepts (not necessarily php vulnerabilities), so work may be done to complete it.  

OBS: It is assumed that given a program slice, if the slice has any vulnerable flow it will pass through the sanitization/validation function (if any).  

# How to run this program:
	./analyzer {patterns file} {slice}  

# Example:
	Input:  
	./analyzer ../test_files/patterns.txt ../test_files/sqli.txt  

	Output:  
	Vulnerability found:  
	SQL Injection  

# Pattern file
Pattern files must have the following structure (an example with the code):  

	{Vulnerability name 1}  
	{Entry point 1},{Entry point 2},{Entry point 3},...  
	{Sanitization/Validation function 1},{Sanitization/Validation function 2},{Sanitization/Validation function 3},...  
	{Sensitive sink 1},{Sensitive sink 2},{Sensitive sink 3},...  

	{Vulnerability name 2}  
	{Entry point 1},{Entry point 2},{Entry point 3},...  
	{Sanitization/Validation function 1},{Sanitization/Validation function 2},{Sanitization/Validation function 3},...  
	{Sensitive sink 1},{Sensitive sink 2},{Sensitive sink 3},...  

	{Vulnerability name 3}  
	{Entry point 1},{Entry point 2},{Entry point 3},...  
	{Sanitization/Validation function 1},{Sanitization/Validation function 2},{Sanitization/Validation function 3},...  
	{Sensitive sink 1},{Sensitive sink 2},{Sensitive sink 3},...  
