
from slowql.parser.tokenizer import Token, Tokenizer, TokenType, tokenize


def test_tokenizer_basic():
    t = Tokenizer()
    tokens = list(t.tokenize("SELECT * FROM users;"))
    assert len(tokens) > 0
    types = [t.type for t in tokens]
    assert TokenType.KEYWORD in types
    assert TokenType.STAR in types
    assert TokenType.IDENTIFIER in types
    assert TokenType.SEMICOLON in types
    assert TokenType.EOF in types

def test_tokenizer_strings():
    tokens = tokenize("SELECT 'string', \"ident\", `mysql_ident`, [tsql_ident]")
    types = [t.type for t in tokens]
    assert TokenType.STRING in types
    assert TokenType.QUOTED_IDENTIFIER in types

def test_tokenizer_numbers():
    tokens = tokenize("SELECT 1, 1.5, .5, 1e10, 1.5E-5")
    num_tokens = [t for t in tokens if t.type == TokenType.NUMBER]
    assert len(num_tokens) == 5

def test_tokenizer_booleans_and_null():
    tokens = tokenize("SELECT TRUE, false, NuLl")
    types = [t.type for t in tokens]
    assert TokenType.BOOLEAN in types
    assert TokenType.NULL in types

def test_tokenizer_comments():
    t = Tokenizer(skip_comments=False)
    tokens = list(t.tokenize("SELECT 1; -- comment\n/* block */"))
    types = [t.type for t in tokens]
    assert TokenType.COMMENT in types
    assert TokenType.BLOCK_COMMENT in types

def test_tokenizer_operators():
    tokens = tokenize("SELECT a + b - c * d / e % f ** g = h != i <> j >= k <= l")
    ops = [t.type for t in tokens if t.type in (TokenType.ARITHMETIC, TokenType.COMPARISON, TokenType.OPERATOR)]
    assert len(ops) > 5

def test_tokenizer_placeholders():
    tokens = tokenize("SELECT $1, :name, ?, @param, %(val)s, %s")
    placeholders = [t for t in tokens if t.type == TokenType.PLACEHOLDER]
    assert len(placeholders) == 6

def test_tokenizer_unknown():
    tokens = tokenize("SELECT ¬") # Unknown char
    unknowns = [t for t in tokens if t.type == TokenType.UNKNOWN]
    assert len(unknowns) == 1

def test_token_properties():
    tok = Token(TokenType.KEYWORD, "SELECT", 1, 1, 1, 6)
    assert tok.is_keyword is True
    assert tok.is_identifier is False
    assert tok.is_literal is False
    assert tok.upper_value == "SELECT"

def test_get_significant_tokens():
    t = Tokenizer(skip_whitespace=False, skip_comments=False)
    sig = t.get_significant_tokens("SELECT 1; -- comment")
    types = [tok.type for tok in sig]
    assert TokenType.WHITESPACE not in types
    assert TokenType.COMMENT not in types
    assert TokenType.EOF not in types
