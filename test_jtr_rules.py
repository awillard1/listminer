#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for John the Ripper rule generation
"""
import sys
import unittest
from pathlib import Path

# Import from listminer module
sys.path.insert(0, str(Path(__file__).parent))
from listminer import (
    jtr_prepend, jtr_append,
    RuleConverter, JohnTheRipperRuleGenerator,
    SCORE_PREPEND_APPEND, SCORE_SURROUND, SCORE_BFS_BASE
)


class TestJtRRuleHelpers(unittest.TestCase):
    """Test basic JtR rule generation helper functions"""
    
    def test_jtr_prepend_single_char(self):
        """Test JtR prepend with single character"""
        result = jtr_prepend("a")
        self.assertEqual(result, "^a")
    
    def test_jtr_prepend_multi_char(self):
        """Test JtR prepend with multiple characters"""
        result = jtr_prepend("abc")
        # Should be reversed: c, b, a
        self.assertEqual(result, "^c^b^a")
    
    def test_jtr_prepend_max_length(self):
        """Test JtR prepend respects max length"""
        result = jtr_prepend("abcdefg", max_length=6)
        self.assertIsNone(result)
    
    def test_jtr_prepend_non_ascii(self):
        """Test JtR prepend rejects non-ASCII"""
        result = jtr_prepend("café")
        self.assertIsNone(result)
    
    def test_jtr_append_single_char(self):
        """Test JtR append with single character"""
        result = jtr_append("a")
        self.assertEqual(result, "$a")
    
    def test_jtr_append_multi_char(self):
        """Test JtR append with multiple characters"""
        result = jtr_append("abc")
        self.assertEqual(result, "$a$b$c")
    
    def test_jtr_append_max_length(self):
        """Test JtR append respects max length"""
        result = jtr_append("abcdefg", max_length=6)
        self.assertIsNone(result)


class TestRuleConverter(unittest.TestCase):
    """Test Hashcat to JtR rule conversion"""
    
    def setUp(self):
        self.converter = RuleConverter()
    
    def test_simple_lowercase(self):
        """Test simple lowercase rule conversion"""
        result = self.converter.hashcat_to_jtr("l")
        self.assertEqual(result, "l")
    
    def test_multiple_operations(self):
        """Test multiple operations are concatenated"""
        result = self.converter.hashcat_to_jtr("l c")
        self.assertEqual(result, "lc")
    
    def test_append_operations(self):
        """Test append operations"""
        result = self.converter.hashcat_to_jtr("$2 $0 $2 $4")
        self.assertEqual(result, "$2$0$2$4")
    
    def test_prepend_operations(self):
        """Test prepend operations"""
        result = self.converter.hashcat_to_jtr("^a ^b ^c")
        self.assertEqual(result, "^a^b^c")
    
    def test_substitute_operations(self):
        """Test substitute operations"""
        result = self.converter.hashcat_to_jtr("sa@ se3")
        self.assertEqual(result, "sa@se3")
    
    def test_toggle_operations(self):
        """Test toggle at position operations"""
        result = self.converter.hashcat_to_jtr("T0 T1")
        self.assertEqual(result, "T0T1")
    
    def test_bitwise_left_filtered(self):
        """Test bitwise left is filtered out"""
        result = self.converter.hashcat_to_jtr("l L c")
        # L should be skipped
        self.assertEqual(result, "lc")
    
    def test_bitwise_right_filtered(self):
        """Test bitwise right is filtered out"""
        result = self.converter.hashcat_to_jtr("l R c")
        # R should be skipped
        self.assertEqual(result, "lc")
    
    def test_is_compatible_true(self):
        """Test compatibility check for valid rules"""
        self.assertTrue(self.converter.is_compatible_with_jtr("l c $2 $0"))
        self.assertTrue(self.converter.is_compatible_with_jtr("^a ^b"))
        self.assertTrue(self.converter.is_compatible_with_jtr("sa@ se3"))
    
    def test_is_compatible_false(self):
        """Test compatibility check for invalid rules"""
        self.assertFalse(self.converter.is_compatible_with_jtr("L"))
        self.assertFalse(self.converter.is_compatible_with_jtr("R"))
        self.assertFalse(self.converter.is_compatible_with_jtr("l L c"))


class TestJohnTheRipperRuleGenerator(unittest.TestCase):
    """Test JtR rule generator class"""
    
    def setUp(self):
        self.generator = JohnTheRipperRuleGenerator()
    
    def test_generate_prepend_rule(self):
        """Test prepend rule generation"""
        result = self.generator.generate_prepend_rule("test")
        self.assertIsNotNone(result)
        score, rule = result
        self.assertEqual(score, SCORE_PREPEND_APPEND)
        # Should be reversed: t, s, e, t
        self.assertEqual(rule, "^t^s^e^t")
    
    def test_generate_append_rule(self):
        """Test append rule generation"""
        result = self.generator.generate_append_rule("test")
        self.assertIsNotNone(result)
        score, rule = result
        self.assertEqual(score, SCORE_PREPEND_APPEND)
        self.assertEqual(rule, "$t$e$s$t")
    
    def test_generate_surround_rule(self):
        """Test surround rule generation"""
        result = self.generator.generate_surround_rule("pre", "suf")
        self.assertIsNotNone(result)
        score, rule = result
        self.assertEqual(score, SCORE_SURROUND)
        # pre reversed: e, r, p and suf: s, u, f
        self.assertEqual(rule, "^e^r^p$s$u$f")
    
    def test_generate_case_rules(self):
        """Test case transformation rules"""
        rules = self.generator.generate_case_rules()
        self.assertGreater(len(rules), 0)
        
        # Check for basic case operations
        rule_strs = [rule for _, rule in rules]
        self.assertIn("l", rule_strs)
        self.assertIn("u", rule_strs)
        self.assertIn("c", rule_strs)
        self.assertIn("t", rule_strs)
    
    def test_generate_toggle_rules(self):
        """Test toggle at position rules"""
        rules = self.generator.generate_toggle_rules([0, 1, 2])
        self.assertEqual(len(rules), 3)
        
        rule_strs = [rule for _, rule in rules]
        self.assertIn("T0", rule_strs)
        self.assertIn("T1", rule_strs)
        self.assertIn("T2", rule_strs)
    
    def test_generate_rotation_rules(self):
        """Test rotation rules"""
        rules = self.generator.generate_rotation_rules()
        self.assertGreater(len(rules), 0)
        
        rule_strs = [rule for _, rule in rules]
        self.assertIn("{", rule_strs)
        self.assertIn("}", rule_strs)
    
    def test_generate_leet_rules_single(self):
        """Test leet-speak rule generation"""
        rules = self.generator.generate_leet_rules("password")
        self.assertGreater(len(rules), 0)
        
        # Verify all rules are valid and don't contain multi-char leet substitutions
        multi_char_leet = ['|-|', '|\\/|', '/\\/\\', '|\\|', '/\\/', '()', '|*', '0_', '|2', '12', 
                           '|_|', '\\/', '|/', '\\/\\/', 'vv', '><', '`/', '_|', '|<', 'ph', '13']
        
        for score, rule in rules:
            # Check that no multi-character leet patterns appear in the rule
            for bad_pattern in multi_char_leet:
                self.assertNotIn(bad_pattern, rule,
                    f"Multi-char leet pattern '{bad_pattern}' found in rule '{rule}'")    
    def test_convert_from_hashcat_rules(self):
        """Test converting Hashcat rules to JtR"""
        hashcat_rules = [
            (1000, "l c"),
            (900, "u"),
            (800, "L"),  # Bitwise, should be filtered
            (700, "sa@ se3"),
        ]
        
        jtr_rules = self.generator.convert_from_hashcat_rules(hashcat_rules)
        
        # Should have 3 rules (L is filtered out)
        self.assertEqual(len(jtr_rules), 3)
        
        # Check converted rules
        rule_strs = [rule for _, rule in jtr_rules]
        self.assertIn("lc", rule_strs)
        self.assertIn("u", rule_strs)
        self.assertIn("sa@se3", rule_strs)


class TestLeetRulesNoMultiChar(unittest.TestCase):
    """Test that leet rules don't generate multi-character substitutions"""
    
    def test_no_multi_char_in_leet_map_usage(self):
        """Ensure multi-char leet substitutions are filtered"""
        from listminer import generate_leet_rules, LEET_MAP
        
        # Test a word that has chars with multi-char leet options
        word = "hamster"  # 'h' has '|-|', 'm' has '|\\/|', etc.
        rules = generate_leet_rules(word, max_substitutions=2)
        
        # Collect all multi-char leet options from the map
        multi_char_leet = []
        for char, options in LEET_MAP.items():
            for option in options:
                if len(option) > 1:
                    multi_char_leet.append(option)
        
        # All generated rules should only use single-char substitutions
        # Multi-char patterns should not appear in any rule
        for rule in rules:
            for bad_pattern in multi_char_leet:
                self.assertNotIn(bad_pattern, rule,
                    f"Multi-char leet option '{bad_pattern}' found in rule '{rule}'")


def run_tests():
    """Run all tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestJtRRuleHelpers))
    suite.addTests(loader.loadTestsFromTestCase(TestRuleConverter))
    suite.addTests(loader.loadTestsFromTestCase(TestJohnTheRipperRuleGenerator))
    suite.addTests(loader.loadTestsFromTestCase(TestLeetRulesNoMultiChar))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
