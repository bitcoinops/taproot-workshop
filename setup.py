# Enter your source directory between the quotes here
SOURCE_DIRECTORY = ''

assert not SOURCE_DIRECTORY == '', 'SOURCE_DIRECTORY not configured'

print("Source directory configured as {}".format(SOURCE_DIRECTORY))

import sys
sys.path.insert(0, SOURCE_DIRECTORY + '/test/functional')
