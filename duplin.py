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
# TODO: add option to only compare filesize (not content hash)
# TODO: add option to control the size of the content to hash
# TODO: add logging/verbosity
# TODO: add disk space freeing by hardlinking.
# TODO: avoid separate stat calls on same file (for file size, mtime, ...). Necessary or does operating system already caches this?
# TODO: add grouping based on users. Would this be useful?

import sys
import os
import optparse
import hashlib
import pprint
import logging
import stat

def main():

    # Handle command line interface
    cliparser = optparse.OptionParser()
    (clioptions, cliargs) = cliparser.parse_args()

    log = logging.getLogger('duplin')
    logging.basicConfig(level=logging.DEBUG)

    # Determine which files to compare
    if len(cliargs) < 1:
        seeds = '.'
    else:
        seeds = cliargs
    file_list = get_file_list(seeds)

    log.debug('Starting analysis of %d files.' % len(file_list))

    # Start with one group of everything
    groups = {(): file_list}
    key_structure = ()

    # TODO: group on relative file path

    # Group on filename
    groups = refine_groups(groups, lambda f: os.path.split(f)[1])
    key_structure += ('filename',)
    log.debug('After filename based grouping: %d groups.' % len(groups))

    # Group on file size
    groups = refine_groups(groups, lambda f: os.path.getsize(f))
    key_structure += ('size',)
    log.debug('After filesize based grouping: %d groups.' % len(groups))

    # Group on modification time
    groups = refine_groups(groups, lambda f: os.stat(f)[stat.ST_MTIME])
    key_structure += ('mtime',)
    log.debug('After mtime based grouping: %d groups.' % len(groups))

    # Group on content hash
    groups = refine_groups(groups, lambda f: md5hash(f))
    key_structure += ('digest',)
    log.debug('After content digest based grouping: %d group.' % len(groups))

    # Remove singletons from last refinement output
    refined_groups = {}
    for key, file_list in groups.iteritems():
        if len(file_list) >= 2:
            refined_groups[key] = file_list
    groups = refined_groups
    log.debug('After singleton cleanup: %d group.' % len(groups))

    # Report
    if len(groups) > 0:
        print "Found these possible duplicates:"
        for key, group in groups.items():
            # TODO: annotate key items better (based on key_structure)
            print '---', key
            for file in group:
                print file
    else:
        print 'No duplicates found'


def get_file_list(seeds):
    '''
    Build file list based on given seeds: file names
    directory names (which will be explored recursively)

    @param seeds list of files or directories

    @return list of
    '''

    file_list = []
    for seed in seeds:
        if os.path.isfile(seed):
            # just add files
            file_list.append(seed)
        elif os.path.isdir(seed):
            # Recursively explore directories
            for (dirpath, dirnames, filenames) in os.walk(seed):
                for filename in filenames:
                    file_list.append(os.path.join(dirpath, filename))
        else:
            raise RuntimeError('Could not find file/directory "{0}"'.format(seed))
    return file_list


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
    for key, file_list in groups.iteritems():
        # Drop singletons.
        if len(file_list) < 2:
            continue
        # Refine real groups.
        for f in file_list:
            subkey = function(f)
            refined_key = key + (subkey,)
            refined_groups[refined_key] = refined_groups.get(refined_key, []) + [f]
    return refined_groups


def md5hash(filename, size=5000):
    '''
    Helper function to calculate MD5 hash of the file contents
    (up to a given number of bytes).

    @param filename file path of file to process
    @param size the maximum number of bytes to read
    '''
    f = open(filename, 'r')
    data = f.read(size)
    f.close()
    return hashlib.md5(data).hexdigest()


if __name__ == '__main__':
    main()
