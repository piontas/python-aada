import six


quote = six.moves.urllib.parse.quote
raw_input = input if six.PY3 else six.moves.input
