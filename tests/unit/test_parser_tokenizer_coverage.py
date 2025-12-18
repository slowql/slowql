from slowql.parser.tokenizer import Token, Tokenizer, TokenType, tokenize


class TestTokenizerCoverage:
    def test_token_properties(self):
        # Keyword
        t_kw = Token(TokenType.KEYWORD, "SELECT", 1, 1, 1, 7)
        assert t_kw.is_keyword
        assert not t_kw.is_identifier
        assert not t_kw.is_literal
        assert not t_kw.is_whitespace
        assert not t_kw.is_comment
        assert t_kw.upper_value == "SELECT"

        # Identifier
        t_id = Token(TokenType.IDENTIFIER, "col", 1, 1, 1, 4)
        assert t_id.is_identifier
        assert not t_kw.is_identifier  # previous check was correct, just double checking logic flow

        # Quoted Identifier
        t_qid = Token(TokenType.QUOTED_IDENTIFIER, '"col"', 1, 1, 1, 6)
        assert t_qid.is_identifier

        # String Literal
        t_str = Token(TokenType.STRING, "'val'", 1, 1, 1, 6)
        assert t_str.is_literal
        # Token doesn't have is_string property

        # Number Literal
        t_num = Token(TokenType.NUMBER, "123", 1, 1, 1, 4)
        assert t_num.is_literal

        # Boolean Literal
        t_bool = Token(TokenType.BOOLEAN, "TRUE", 1, 1, 1, 5)
        assert t_bool.is_literal

        # Null Literal
        t_null = Token(TokenType.NULL, "NULL", 1, 1, 1, 5)
        assert t_null.is_literal

        # Whitespace
        t_ws = Token(TokenType.WHITESPACE, " ", 1, 1, 1, 2)
        assert t_ws.is_whitespace

        t_nl = Token(TokenType.NEWLINE, "\n", 1, 1, 2, 1)
        assert t_nl.is_whitespace

        # Comments
        t_cmt = Token(TokenType.COMMENT, "-- c", 1, 1, 1, 5)
        assert t_cmt.is_comment

        t_blk = Token(TokenType.BLOCK_COMMENT, "/*c*/", 1, 1, 1, 6)
        assert t_blk.is_comment

    def test_tokenizer_patterns(self):
        tokenizer = Tokenizer()

        # Comments
        tokens = tokenizer.get_tokens("-- comment\nSELECT")
        assert tokens[0].type == TokenType.COMMENT

        tokens = tokenizer.get_tokens("/*\nblock\n*/")
        assert tokens[0].type == TokenType.BLOCK_COMMENT

        # Strings
        tokens = tokenizer.get_tokens("'str' E'esc' $$dollar$$")
        assert tokens[0].type == TokenType.STRING
        assert tokens[2].type == TokenType.STRING
        assert tokens[4].type == TokenType.STRING

        # Quoted identifiers
        tokens = tokenizer.get_tokens('"id" `id` [id]')
        # Filter mostly to ignore potential whitespace depending on regex impl details
        real_tokens = [t for t in tokens if t.type == TokenType.QUOTED_IDENTIFIER]
        assert len(real_tokens) == 3

        # Numbers
        tokens = tokenizer.get_tokens("123 12.34 .5 1e10")
        nums = [t for t in tokens if t.type == TokenType.NUMBER]
        assert len(nums) == 4

        # Placeholders
        tokens = tokenizer.get_tokens("$1 :param ? @param %(p)s %s")
        placeholders = [t for t in tokens if t.type == TokenType.PLACEHOLDER]
        assert len(placeholders) == 6

        # Operators
        tokens = tokenizer.get_tokens(":: <> != >= <= <=> !< !> || && ** << >>")
        operators = [
            t
            for t in tokens
            if t.type
            in (
                TokenType.DOUBLE_COLON,
                TokenType.COMPARISON,
                TokenType.LOGICAL,
                TokenType.ARITHMETIC,
            )
        ]
        assert len(operators) >= 11

        # Single chars - use separate string to avoid operator interference
        tokens = tokenizer.get_tokens("( ) , ; . : *")
        singles = [
            t
            for t in tokens
            if t.type
            in (
                TokenType.LPAREN,
                TokenType.RPAREN,
                TokenType.COMMA,
                TokenType.SEMICOLON,
                TokenType.DOT,
                TokenType.COLON,
                TokenType.STAR,
            )
        ]
        assert len(singles) == 7

    def test_keywords_and_special_values(self):
        tokenizer = Tokenizer()
        tokens = tokenizer.get_tokens("SELECT TRUE FALSE NULL unknown_id")
        significant = [t for t in tokens if not t.is_whitespace and t.type != TokenType.EOF]

        assert significant[0].type == TokenType.KEYWORD
        assert significant[1].type == TokenType.BOOLEAN
        assert significant[2].type == TokenType.BOOLEAN
        assert significant[3].type == TokenType.NULL
        assert significant[4].type == TokenType.IDENTIFIER

    def test_skip_behavior(self):
        # Skip whitespace
        tokenizer = Tokenizer(skip_whitespace=True)
        tokens = tokenizer.get_tokens("SELECT *")
        # tokens should be SELECT, STAR, EOF (3 tokens)
        assert len(tokens) == 3
        assert tokens[0].value == "SELECT"
        assert tokens[1].value == "*"
        assert tokens[2].type == TokenType.EOF

        # Skip comments
        tokenizer = Tokenizer(skip_comments=True)
        tokens = tokenizer.get_tokens("SELECT -- cmt")
        # tokens: SELECT, WHITESPACE, EOF (no comment)
        # Note: trailing whitespace depends on input. Here space before -- matches pattern.
        # "SELECT " -> SELECT, WHITESPACE.
        tok_types = [t.type for t in tokens]
        assert TokenType.COMMENT not in tok_types

    def test_multiline_tracking(self):
        tokenizer = Tokenizer()
        sql = "SELECT\n*"
        tokens = tokenizer.get_tokens(sql)
        # SELECT (line 1)
        # \n (line 1, ends line 2)
        # * (line 2)

        sel = tokens[0]
        nl = tokens[1]
        star = tokens[2]

        assert sel.line == 1
        assert nl.type == TokenType.NEWLINE
        assert nl.line == 1
        assert nl.end_line == 2
        assert star.line == 2
        assert star.column == 1

    def test_unknown_char(self):
        tokenizer = Tokenizer()
        tokens = tokenizer.get_tokens("#")  # # is not in patterns
        assert tokens[0].type == TokenType.UNKNOWN
        assert tokens[0].value == "#"

    def test_get_significant_tokens(self):
        tokenizer = Tokenizer()
        tokens = tokenizer.get_significant_tokens("SELECT -- cmt\n *")
        # Should contain SELECT, *
        assert len(tokens) == 2
        assert tokens[0].value == "SELECT"
        assert tokens[1].value == "*"

    def test_tokenize_helper(self):
        tokens = tokenize("SELECT *", skip_whitespace=True)
        # Should be list of tokens without EOF
        assert len(tokens) == 2
        assert tokens[0].value == "SELECT"
        assert tokens[1].value == "*"
