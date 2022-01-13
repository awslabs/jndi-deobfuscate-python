#!/usr/bin/env python3

import itertools
import logging
import re
from multiprocessing import Pool
from typing import Dict, List, Tuple, Union
from urllib.parse import unquote

# after light processing, this is the maximum number of times a given string should be attempted to be transformed
# (ex: url decoded, base64 decoded, etc.)
MAX_RECURSION_PER_STRING = 100
MAX_URL_DECODE_ATTEMPTS = 10

SIMPLE_JNDI_REGEX_PATTERN = r"\$\{.*:.*:.*\}"

# Two match groups below: Group 1: the full JNDI string. Group 2: the extracted default value
SIMPLE_DEFAULT_VALUE_REGEX_PATTERN = r"(\${[A-Za-z0-9_\-\.\:]*:-([A-Za-z0-9_\-\.\:]*[^\$])})"

# Three match groups below: Group 1: everything; Group 2: modifier (upper/lower); Group 3: text to be modified
SIMPLE_UPPER_LOWER_MODIFIER_REGEX_PATTERN = r"(\${(upper|lower):([A-Za-z0-9_\-.]*[^\$:])})"

SIMPLE_LOOKUP_REGEX_PATTERNS = {
    "DATE_LOOKUP": r"\$\{date:[^\$][^}]*\}",
    "CONTEXT_MAP_LOOKUP": r"\$\{ctx:[^\$][^}]*\}",
    "MAIN_ARGS_LOOKUP": r"\$\{main:[^\$][^}]*\}",
    "JMX_ARGS_LOOKUP": r"\$\{jvmrunargs:[^\$][^}]*\}",
    "MAP_LOOKUP": r"\$\{map:[^\$][^}]*\}",
    "STRUCTURED_DATA_LOOKUP": r"\$\{sd:[^\$][^}]*\}",
    "WEB_LOOKUP": r"\$\{web:[^\$][^}]*\}",
}

logger = logging.getLogger(__name__)


def _transform_url_decode(input_string: str) -> str:
    """Turns URL encoded data (te%20st), into non-URL encoded data (te st), for further processing"""
    decode_attempts = 0
    output_string = input_string
    if output_string:
        while decode_attempts <= MAX_URL_DECODE_ATTEMPTS:
            decode_attempts = decode_attempts + 1
            url_decoded_data = unquote(output_string)
            if output_string != url_decoded_data:
                output_string = url_decoded_data
            else:
                # no changes were made, we are done processing
                break
    return output_string


def _does_string_pass_simple_jndi_regex(input_string: str) -> bool:
    """Returns True/False if string contains at least one JNDI match, based on a simple regex"""
    result = re.search(SIMPLE_JNDI_REGEX_PATTERN, input_string)
    if result:
        logger.debug(f"String passes simple JNDI regex: `{input_string}`")
        return True
    else:
        logger.debug(f"String does not pass simple JNDI regex: `{input_string}`")
        return False


def does_it_meet_the_bare_minimum_checks_for_java_lookups(input_string: str) -> bool:
    "Returns True/False, based on if the string contains characteristics of possibly containing a Java lookup (incl. JNDI) string. (used for filtering)"
    output = False
    if input_string:
        if "${" not in input_string:
            logger.debug("Invalid JNDI - does not contain `${`")
        else:

            output = _does_string_pass_simple_jndi_regex(input_string)
    return output


def _guess_number_of_curley_brace_pairs(input_string: str) -> int:
    """Returns the number of possibly matched curley brace pairs. Note: Just does a count, does not actually attempt to match pairs up."""
    number_of_left_curley_braces = 0
    number_of_right_curley_braces = 0
    if input_string:
        number_of_left_curley_braces = input_string.count("{")
        number_of_right_curley_braces = input_string.count("}")
        if number_of_left_curley_braces != number_of_right_curley_braces:
            logger.debug(
                f"Possible Invalid JNDI - incorrect number of curley braces. (L:{number_of_left_curley_braces}; R:{number_of_right_curley_braces}) "
            )
    curley_brace_pairs = [number_of_left_curley_braces, number_of_right_curley_braces]
    return min(curley_brace_pairs)


def _transform_return_string_that_passes_basic_jndi_validation(input_string: str) -> str:
    """Returns a string that possibly contains a JNDI string - not using regex (used for filtering)
    Note: Added to filter garbled strings that passed initial validation"""
    output = None
    if input_string:
        input_string = input_string.strip()
        if input_string.lower().startswith("${jndi:") and input_string.endswith("}"):
            output = input_string
            logger.debug(f"Validated JNDI using starts/ends-with: `{input_string}`.")
        else:
            logger.debug(
                f"This almost got through, but doesn't look right: `{input_string}` - consider adding this to test cases, and updating regexes to be more strict."
            )

    return output


def _transform_get_first_jndi_string(input_string: str) -> Union[str, bool]:
    """Returns string contained in first set of curley braces found (incl. braces) (used for filtering)"""
    output = None
    if input_string:
        result = re.findall(SIMPLE_JNDI_REGEX_PATTERN, input_string)
        if result:
            regex_output = result[0]
            logger.debug(
                f"Curley brace search: found first JNDI string via regex: `{regex_output}`"
            )
            first_left_curley_brace_position = regex_output.find("${")
            first_right_curley_brace_position = (
                regex_output[first_left_curley_brace_position:].find("}") + 1
            )
            first_jndi_string = str(
                regex_output[first_left_curley_brace_position:first_right_curley_brace_position]
            )
            output = first_jndi_string
            if regex_output != first_jndi_string:
                logger.debug(
                    f"Curley brace search: extracted first JNDI string `{first_jndi_string}` from initial regex output {regex_output}"
                )
    return output


def _does_string_have_unresolved_variables_with_default_values(input_string: str) -> bool:
    """Returns True/False, if string uses a JNDI/Java lookup feature, known as `unresolved variables with default values` (UVWDV)
    This is used for filtering, because our current UVWDV processing is very resource intensive.
    """
    if input_string:
        result = re.search(SIMPLE_DEFAULT_VALUE_REGEX_PATTERN, input_string)
        if result:
            return True
        else:
            return False
    else:
        return False


def _transform_extract_default_values_from_unresolved_variables(
    input_string: str,
) -> Tuple[str, str]:
    """Given a JNDI substring, that contains a JNDI/Java feature known as `unresolved variables with default values`, this method will attempt
    to provide the intended default value, from the unresolved variable string
    """
    result = re.search(SIMPLE_DEFAULT_VALUE_REGEX_PATTERN, input_string)
    # is this necessary? we already did this check:
    if result:
        full_variable = result.group(1)
        default_value = result.group(2)
        return full_variable, default_value
    else:
        return (False, False)


def _transform_replace_default_values_from_unresolved_variables(input_string: str) -> str:
    # TODO: when you implement order-of-operations, only do this AFTER multi-letter string replacement.
    # (the other variables may cause this to test positive.)
    """Given a JNDI string, that contains a JNDI/Java feature known as `unresolved variables with default values` (UVWDV), this method will attempt
    to deobfuscate the string by replacing all of those UVWDV with the intended default values.
    """
    output_string = input_string
    if _does_string_have_unresolved_variables_with_default_values(output_string):
        (
            full_variable,
            default_value,
        ) = _transform_extract_default_values_from_unresolved_variables(output_string)
        if full_variable and default_value:
            output_string = input_string.replace(full_variable, default_value)
    return output_string


def _transform_replace_simple_lookups(input_string: str) -> str:
    """Given a string containing a JNDI/Java lookup features (that we mark as 'simple' internally), replace those lookups
    with appropriate strings. An example is a date lookup string (${date:...})

    This method is called 'simple', because it is exclusively looking for lookups that are correctly formed.
    For lookups that are using the JNDI/Java feature known as `unresolved variables with default values` (which attackers may
    use to obfuscate their attack string), this 'simple' lookup method  is not used. (Instead, methods using the term `unresolved_variables_with_default_values` are used.)
    """
    output_string = input_string
    if output_string is not None:
        # we need to prioritize replacing unresolved vars, before we try replacing with simple lookup strings
        if not _does_string_have_unresolved_variables_with_default_values(input_string):
            for lookup_name, lookup_regex in SIMPLE_LOOKUP_REGEX_PATTERNS.items():
                lookup_found = re.search(lookup_regex, output_string)
                if lookup_found:
                    output_string = re.sub(lookup_regex, lookup_name, output_string)
    return output_string


def _transform_replace_upper_and_lower_methods(input_string: str) -> str:
    """Given a string with Java lookup features using either upper() or lower() modifiers,
    deobfuscate the string by replacing those features with the appropriate text.
    """
    if input_string:
        result = re.search(SIMPLE_UPPER_LOWER_MODIFIER_REGEX_PATTERN, input_string)
        if result:

            full_variable = result.group(1)  # ${lower:TEXT_TO_LOWER}
            modifier = result.group(2)  # lower/upper
            text_to_modify = result.group(3)  # TEXT_TO_LOWER
            if modifier.lower() == "lower":
                modified_text = text_to_modify.lower()

            elif modifier.lower() == "upper":
                modified_text = text_to_modify.upper()
            else:
                logger.debug(
                    f"Upper/lower found unknown modifier: {modifier} in string {full_variable}"
                )

            output_string = input_string.replace(full_variable, modified_text)
            return output_string

        else:
            return input_string


def _return_all_case_variations(input_string) -> List[str]:
    "given a string, returns a list of strings, containing all combinations of uppercase/lowercase for that string"
    return list(
        map(
            "".join,
            itertools.product(
                *(sorted(set((character.upper(), character.lower()))) for character in input_string)
            ),
        )
    )


VARIABLE_REPLACEMENT_DICT = {
    # Cloud Provider-specific variables
    "ENV_AWS_ACCESS_KEY": "${env:AWS_ACCESS_KEY}",
    "ENV_AWS_ACCESS_KEY_ID": "${env:AWS_ACCESS_KEY_ID}",
    "ENV_AWS_SECRET_ACCESS_KEY": "${env:AWS_SECRET_ACCESS_KEY}",
    "ENV_AWS_DEFAULT_REGION": "${env:AWS_DEFAULT_REGION}",
    "ENV_AZURE_ACCOUNT_KEY": "${env:ACCOUNT_KEY}",
    "ENV_AZURE_RESOURCE_GROUP_NAME": "${env:RESOURCE_GROUP_NAME}",
    "ENV_AZURE_STORAGE_ACCOUNT_NAME": "${env:STORAGE_ACCOUNT_NAME}",
    "ENV_AZURE_SYSTEM_ACCESSTOKEN": "${env:SYSTEM_ACCESSTOKEN}",
    # System/Java Variables
    "ENV_DB_HOST": "${env:DB_HOST}",
    "ENV_DB_USERNAME": "${env:DB_USERNAME}",
    "ENV_DB_PASS": "${env:DB_PASS}",
    "ENV_DB_PASSWORD": "${env:DB_PASSWORD}",
    "ENV_HOSTNAME": "${env:HOSTNAME}",
    "ENV_JAVA_VERSION": "${env:JAVA_VERSION}",
    "ENV_PORT": "${env:PORT}",
    "ENV_USERNAME": "${env:USERNAME}",
    "ENV_USER": "${env:USER}",
    "ENV_PASSWORD": "${env:PASSWORD}",
    "ENV_DATABASE": "${env:DATABASE}",
    "ENV_DATABASE_URL": "${env:DATABASE_URL}",
    "ENV_JDBC_DATABASE_URL": "${env:JDBC_DATABASE_URL}",
    "ENV_REDIS_URL": "${env:REDIS_URL}",
    "ENV_CA_CERT": "${env:CA_CERT}",
    "ENV_WINDOWS_COMPUTERNAME": "${env:COMPUTERNAME}",
    "ENV_WINDOWS_LOGONSERVER": "${env:LOGONSERVER}",
    "ENV_WINDOWS_USERDOMAIN": "${env:USERDOMAIN}",
    "VAR_HOSTNAME": "${HOSTNAME}",
    "VAR_SYS_HOSTNAME": "${sys:hostname}",
    "VAR_SYS_JAVA_VENDOR": "${sys:java.vendor}",
    "VAR_SYS_JAVA_VERSION": "${sys:java.version}",
    "VAR_SYS_OS_NAME": "${sys:os.name}",
    "VAR_SYS_OS_VERSION": "${sys:os.version}",
    "VAR_SYS_USER_NAME": "${sys:user.name}",
    "VAR_SYS_USER_DIR": "${sys:user.dir}",
    "VAR_JAVA_HW": "${java:hw}",
    "VAR_JAVA_LOCALE": "${java:locale}",
    "VAR_JAVA_OS": "${java:os}",
    "VAR_JAVA_RUNTIME": "${java:runtime}",
    "VAR_JAVA_VERSION": "${java:version}",
    "VAR_JAVA_VM": "${java:vm}",
    "WEB_LOOKUP_CONTEXT_PATH": "${web:contextPath}",
    "WEB_LOOKUP_EFFECTIVE_MAJ_VERSION": "${web:effectiveMajorVersion}",
    "WEB_LOOKUP_EFFECTIVE_MIN_VERSION": "${web:effectiveMinorVersion}",
    "WEB_LOOKUP_MAJ_VERSION": "${web:majorVersion}",
    "WEB_LOOKUP_MIN_VERSION": "${web:minorVersion}",
    "WEB_LOOKUP_ROOT_DIR": "${web:rootDir}",
    "WEB_LOOKUP_SERVER_INFO": "${web:serverInfo}",
    "WEB_LOOKUP_SERVLET_CONTEXT_NAME": "${web:servletContextName}",
}


def _is_replace_obfuscation_necessary(input_string: str) -> bool:
    """Optimization: if the string can't have any variables in it, don't do any work."""
    output = False
    if input_string:
        pairs = _guess_number_of_curley_brace_pairs(input_string)
        if pairs > 1:
            output = True
    return output


def _transform_replace_obfuscated_variable(initial_string: str) -> str:
    """Given a JNDI string using features to obfuscate a static string, return a deobfuscated string by
    replacing those features with the appropriate multiple character groups."""
    accumulator = initial_string
    lowered = initial_string.lower()

    for key in VARIABLE_REPLACEMENT_DICT.keys():
        special_string_lowered = VARIABLE_REPLACEMENT_DICT[key].lower()
        while special_string_lowered in lowered:
            special_string_index = lowered.find(special_string_lowered)
            accumulator = (
                f"{accumulator[:special_string_index]}"
                f"{key}"
                f"{accumulator[special_string_index+ len(special_string_lowered):]}"
            )
            lowered = accumulator.lower()
    return accumulator


def _run_transform_return_output(
    method_name: str, input_string: str, print_debug: bool = False
) -> Tuple[bool, Dict[str, str]]:
    """This is a wrapper for transformation methods, and it adds checks/logging. The output determines if
    a specific transformation changed anything (which is used from the calling method, to break a loop.)
    """
    has_changed = False
    if not input_string:

        output_dict = {"input_string": False, "output_string": False}
    else:
        input_string = input_string.strip()
        output_string = globals()[method_name](input_string)

        if output_string:
            output_string = output_string.strip()
            if input_string != output_string:
                has_changed = True
                if print_debug:
                    logger.debug(
                        f"Transform `{method_name}` changed `{input_string}` into `{output_string}`"
                    )

            output_dict = {"input_string": input_string, "output_string": output_string}
        else:
            output_dict = {"input_string": False, "output_string": False}
    return (has_changed, output_dict)


def process_line(line: str, print_output: bool = True, print_debug: bool = True):
    """Given a single line, return any possible JNDI strings by running a number of deobfuscation methods."""
    if line:
        logger.debug(f"initial line is {line.strip()}")

    transform_method_names = [
        "_transform_url_decode",
        "_transform_replace_obfuscated_variable",
        "_transform_replace_upper_and_lower_methods",
        "_transform_replace_simple_lookups",
        "_transform_replace_default_values_from_unresolved_variables",
        "_transform_get_first_jndi_string",
        "_transform_return_string_that_passes_basic_jndi_validation",
    ]
    number_of_loops_ran = 0
    while number_of_loops_ran <= MAX_RECURSION_PER_STRING:
        number_of_loops_ran += 1

        if line is None:
            if print_debug:
                logger.debug(
                    f"Processing line is now empty; escaping this loop at count {number_of_loops_ran}"
                )
                break

        if print_debug:
            logger.debug(f"Processing line - loop number: {number_of_loops_ran}")
        line_at_beginning = line

        for transform in transform_method_names:
            has_changed, processed_data = _run_transform_return_output(
                method_name=transform,
                input_string=line,
                print_debug=print_debug,
            )
            if has_changed:
                line = processed_data["output_string"]
                logger.debug("Processing line - Line has changed; starting transforms over again")
                break
            if not processed_data["input_string"] or not processed_data["output_string"]:
                logger.debug(
                    "Processing line - at least one transform returned an empty set. returning None."
                )
                return None
        line_at_end = line
        if line_at_beginning == line_at_end:
            logger.debug(f"Processing line - recursion count for string is: {number_of_loops_ran}")
            if print_output:
                print(line)
            else:
                return line
            break

        if number_of_loops_ran == MAX_RECURSION_PER_STRING:
            logger.debug(f"Processing line - max recursion reached for string `{line}`")


def process_file(file_name: str, number_of_processes: int = 8) -> List[str]:
    """Given a filename, process each line of text (separated by newline), return any possible JNDI strings by running a number of deobfuscation methods."""
    file = open(file_name)
    lines_to_process = []
    for line in file:
        lines_to_process.append(line)
    pool = Pool(number_of_processes)
    results = pool.map(process_line, lines_to_process)
    return results


if __name__ == "__main__":
    import argparse
    import sys
    from os.path import exists

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-f",
        "--filename",
        dest="file",
        default="",
        help="Provide filename to process, newline separated",
        type=str,
    )
    parser.add_argument(
        "-s",
        "--string",
        dest="string",
        default="",
        help="Provide a string to process (limit 1 extraction). Surround with single quotes to avoid issues in your terminal.",
        type=str,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        dest="verbose",
        default=False,
        action="store_true",
        help="Print debug logging to stderr (for development or troubleshooting)",
    )
    args = parser.parse_args()
    if args.verbose:
        logger.debug("Verbose mode enabled")
        logging.basicConfig(stream=sys.stderr, format="%(levelname)s : %(funcName)s : %(message)s")
        logger.setLevel(logging.DEBUG)

    if exists(args.file):
        process_file(args.file)
    elif args.string:
        process_line(args.string)
