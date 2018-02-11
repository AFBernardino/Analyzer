#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "lists.h"

// returns a list of patterns with patterns imported from file_path
node_pattern * import_patterns(char * file_path) {
	int character = 0;
	int char_length = 0;
	char * str = NULL;
	int pattern_line = 1;		// line of the pattern: vulnerability name, sinks, ...
	long int curr = 0;		// current position of pointer in file

	//create list of patterns
	node_pattern * pattern_list = create_pattern_list();
	if (pattern_list == NULL) {
		fprintf(stdout, "Error creating list of patterns.");
		return NULL;
	}

	pattern * patt = NULL;

	FILE * fp = fopen(file_path, "r");

	// fail fast
	if (fp == NULL) {
		fprintf(stdout, "Could not open file: %s\n", file_path);
		return NULL;
	}

	while (!feof(fp)) {
		character = fgetc(fp);
		char_length = char_length + 1;

		if (character == '\n' || character == ',') {			
			str = (char *) malloc((char_length + 1) * sizeof(char));
			curr = ftell(fp);		// save pointer position

			fseek(fp, -(char_length), SEEK_CUR);	// go back to the beginning of the string
			fread(str, char_length - 1, 1, fp);		//read the string
			fseek(fp, curr, SEEK_SET);		// relocate pointer

			// add string to pattern struct
			switch (pattern_line) {
				case 1:		// new pattern
					patt = create_pattern_struct();
					add_pattern(pattern_list, patt);
					patt->vuln_name = str;
					break;
				case 2:
					add_string(patt->entry_points, str);
					break;
				case 3:
					add_string(patt->sanit_funcs, str);
					break;
				case 4:
					add_string(patt->sinks, str);
					break;
			}

			// get next pattern line
			if (character == '\n') {
				pattern_line = pattern_line + 1;
				if (pattern_line > 5) {		// end of pattern
					pattern_line = 1;
				}
			}

			char_length = 0;
		}
	}

	fclose(fp);		// close file

	return pattern_list;
}

// return slice content
char * get_slice_content(char * file_path) {
	FILE * fp = fopen(file_path, "r");

	if (fp == NULL) {
		fprintf(stdout, "Could not open file: %s\n", file_path);
		return NULL;
	}

	// get slice size
	fseek(fp, 0, SEEK_END);
	long fsize = ftell(fp);

	// read slice content
	fseek(fp, 0, SEEK_SET);
	char * content = malloc(fsize + 1);
	fread(content, fsize, 1, fp);
	content[fsize] = '\0';

	fclose(fp);		// close slice

	return content;
}

// return vulnerability (if any) and find sanitization/validation functions from slice (if any)
char * scan_slice(char * slice_path, node_pattern * pattern_list, node_str * sanitization_funcs) {
	char * vulnerability = NULL;
	char * slice_content = get_slice_content(slice_path);
	bool found = false;

	// fail fast
	if (slice_content == NULL || pattern_list == NULL) {
		return NULL;
	}

	// loop patterns
	node_pattern * current_pattern = pattern_list;
    while (current_pattern != NULL) {
    	/***** Vulnerability space *****/
    	// loop entry points
		node_str * current_ep = current_pattern->pattern->entry_points;
        while (current_ep != NULL) {
			if (current_ep->str != NULL && strstr(slice_content, current_ep->str) != NULL) {
				found = true;
				break;
			}
			current_ep = current_ep->next;
		}

		if (found) {
			found = false;

			// loop sinks
			node_str * current_sink = current_pattern->pattern->sinks;
		    while (current_sink != NULL) {
				if (current_sink->str != NULL && strstr(slice_content, current_sink->str) != NULL) {
					found = true;
					break;
				}
				current_sink = current_sink->next;
			}
		}
		/**********/

		/***** Sanitization/Validation space *****/
		if (found) {
			// loop sanitization functions
			node_str * current_sfunc = current_pattern->pattern->sanit_funcs;
		    while (current_sfunc != NULL) {
				if (current_sfunc->str != NULL && strstr(slice_content, current_sfunc->str) != NULL) {
					found = false;
					add_string(sanitization_funcs, current_sfunc->str);
				}
				current_sfunc = current_sfunc->next;
			}
		}
		/**********/

		// vulnerability found!
		if (found) {
			found = false;
			vulnerability = current_pattern->pattern->vuln_name;
			break;
		}

		current_pattern = current_pattern->next;
    }

	free(slice_content);		// free memory

	return vulnerability;
}

// main function
int main(int argc, char * argv[]) {
	if (argc > 2) {
		node_pattern * pattern_list = import_patterns(argv[1]);		// import patterns
		node_str * sanitization_funcs = create_string_list();		// create sanitization functions list

		char * vulnerability = scan_slice(argv[2] ,pattern_list, sanitization_funcs);

		// print vulnerability (if any)
		if (vulnerability != NULL) {
			fprintf(stdout, "Vulnerability found:\n%s\n", vulnerability);

		// print sanitization/validation functions (if any)
		} else if (!is_empty(sanitization_funcs)) {
			fprintf(stdout, "No vulnerability found.\nSanitization/Validation functions found:\n");
			print_string_list(sanitization_funcs);

		// nothing found
		} else {
			fprintf(stdout, "No vulnerability found.\n");
		}

		// free memory
		free_pattern_list(pattern_list);
		free_string_list(sanitization_funcs);

	} else {
		fprintf(stdout, "Missing arguments: Try: ./analyzer {patterns file} {slice}\n");
	}
}

