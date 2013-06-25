#!/usr/bin/env python
##############################################################################
# Copyright 2012 Stefaan Lippens
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
##############################################################################

'''
Tool to search for file duplicates, based on a selectable subset of indicators
(file size, attributes, filename, relative path, content, ...

Found duplicates are reported and can optionally be "compressed" by hardlinking.
'''

# TODO: add option to control size representation (human readable, kB, kiB, ...)
# TODO: add option to exclude paths/patterns from recursive directory exploring
# TODO: show progress bar?
# TODO: add option to control the size of the content to hash
# TODO: add disk space freeing by hardlinking.
# TODO: avoid separate stat calls on same file (for file size, mtime, ...). Necessary or does operating system already caches this?
# TODO: add grouping based on users. Would this be useful?
# TODO: group on relative file path

import sys
import os
import optparse
import hashlib
import pprint
import logging
import stat

_log = logging.getLogger('duplin')


def main():

    # Get arguments and options from command line
    (clioptions, cliargs) = get_options_and_arguments_from_cli()

    # Set up logging
    global _log
    level = logging.WARNING
    if clioptions.verbose:
        level = logging.DEBUG
    logging.basicConfig(level=level)

    # Determine which files to compare
    if len(cliargs) < 1:
        seeds = ['.']
    else:
        seeds = cliargs
    files = collect_files(seeds)

    _log.debug('Starting analysis of %d files.' % len(files))

    # Put the duplication indicators in a dictionary to pass as kwargs below.
    duplication_indicator_options = {
        'group_on_filename': clioptions.group_on_filename,
        'group_on_filesize': clioptions.group_on_filesize,
        'group_on_content': clioptions.group_on_content,
        'group_on_mtime':  clioptions.group_on_mtime,
    }
    # If all indicator are disabled: do not set duplication indicator options, so the defaults are used.
    if reduce(lambda x, y: x or y, duplication_indicator_options.values(), False) == False:
        duplication_indicator_options = {}

    # Split the file list in groups based on the duplication indicator options.
    groups = duplin(files, **duplication_indicator_options)

    # Report
    if len(groups) > 0:
        print "Found these %d sets of possible duplicates:" % len(groups)
        for key, group in groups.items():
            # TODO: annotate key items better (based on key_structure)
            print '---', key
            for file in group:
                print file
    else:
        print 'No duplicates found'


def duplin(files, group_on_filesize=True, group_on_content=True, group_on_filename=False, group_on_mtime=False):
    '''
    Split the given file set in duplicate groups based on the given duplication indicators
    '''
    global _log

    # Start with one group of everything
    groups = {(): files}
    key_structure = ()

    if group_on_filename:
        # Group on filename
        groups = refine_groups(groups, lambda f: os.path.split(f)[1])
        key_structure += ('filename',)
        _log.debug('After filename based grouping: %d groups.' % len(groups))

    if group_on_filesize:
        # Group on file size
        groups = refine_groups(groups, lambda f: os.path.getsize(f))
        key_structure += ('size',)
        _log.debug('After filesize based grouping: %d groups.' % len(groups))

    if group_on_mtime:
        # Group on modification time
        groups = refine_groups(groups, lambda f: os.stat(f)[stat.ST_MTIME])
        key_structure += ('mtime',)
        _log.debug('After mtime based grouping: %d groups.' % len(groups))

    if group_on_content:
        # Group on content hash
        groups = refine_groups(groups, lambda f: md5hash(f))
        key_structure += ('digest',)
        _log.debug('After content digest based grouping: %d group.' % len(groups))

    # Remove singletons from last refinement output
    refined_groups = {}
    for key, files in groups.iteritems():
        if len(files) >= 2:
            refined_groups[key] = files
    groups = refined_groups
    _log.debug('After singleton cleanup: %d group.' % len(groups))

    return groups


def get_options_and_arguments_from_cli():
    '''
    Helper function to build and use a command line argument parser.
    '''

    # Build the command line parser
    cliparser = optparse.OptionParser()

    # Duplication indicator options.
    indicator_option_group = optparse.OptionGroup(
        cliparser,
        title="Duplication indicator options",
        description="Enable one or more of these duplication indicators. If none are set, a default subset will be used."
    )
    indicator_option_group.add_option(
        '-c', '--content',
        action='store_true', dest='group_on_content', default=False,
        help='Use file content (digest) as duplication indicator.'
    )
    indicator_option_group.add_option(
        '-f', '--filename',
        action='store_true', dest='group_on_filename', default=False,
        help='Use file name (just basename, not path) as duplication indicator.'
    )
    indicator_option_group.add_option(
        '-s', '--size',
        action='store_true', dest='group_on_filesize', default=False,
        help='Use file size as duplication indicator.'
    )
    indicator_option_group.add_option(
        '-m', '--mtime',
        action='store_true', dest='group_on_mtime', default=False,
        help='Use file last modification time as duplication indicator.'
    )
    cliparser.add_option_group(indicator_option_group)

    # Misc options.
    cliparser.add_option(
        '-v', '--verbose',
        action='store_true', dest='verbose', default=False,
        help='Show more runtime information.')


    # Use the command line argument parser
    (clioptions, cliargs) = cliparser.parse_args()
    return (clioptions, cliargs)


def collect_files(seeds):
    '''
    Build file list based on given seeds: file names
    directory names (which will be explored recursively)

    @param seeds list of files or directories

    @return set of file paths (relative to given seed paths)
    '''

    files = set()
    for seed in seeds:
        if os.path.isfile(seed):
            # just add files
            files.add(seed)
        elif os.path.isdir(seed):
            # Recursively explore directories
            for (dirpath, dirnames, filenames) in os.walk(seed):
                for filename in filenames:
                    files.add(os.path.join(dirpath, filename))
        else:
            raise RuntimeError('Could not find file/directory "{0}"'.format(seed))
    return files


def refine_groups(groups, function):
    '''
    Refine a grouping of files based on the given hash function.
    As application specific optimization, singletons in the input
    grouping will be ignored. However, the output grouping can still
    contain singletons.

    @param groups a dictionary mapping keys to file lists.

    @return new dictionary mapping refined keys to refined groups
    '''
    refined_groups = {}
    for key, files in groups.iteritems():
        # Drop singletons.
        if len(files) < 2:
            continue
        # Refine real groups.
        for f in files:
            # Apply function to refine file key
            subkey = function(f)
            refined_key = key + (subkey,)
            # Reassign to refined groups.
            if refined_key not in refined_groups:
                refined_groups[refined_key] = set()
            refined_groups[refined_key].add(f)
    return refined_groups


def md5hash(filename, size=50000):
    '''
    Helper function to calculate MD5 hash of the file contents
    (up to a given number of bytes).

    @param filename file path of file to process
    @param size the maximum number of bytes to read
    '''
    f = open(filename, 'r')
    data = f.read(size)
    f.close()
    hash = hashlib.md5(data).hexdigest()
    del data
    return hash


if __name__ == '__main__':
    main()
