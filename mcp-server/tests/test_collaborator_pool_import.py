"""Regression: _payloads referenced _COLLAB_POOL without importing it.

generate_collaborator_payload / _pool / collaborator_pool_status all touch
the shared _COLLAB_POOL list, but _payloads imported only _pool_lock — so
every one of them raised NameError('_COLLAB_POOL') at call time, breaking
all OOB payload generation (Burp Collaborator unusable via the MCP tools).

The pool tools mutate the list in place (extend/pop), so the name must be
bound to the SAME object _oast defines, not a copy.
"""

import unittest

from praetor.tools.collaborate import _oast, _payloads


class CollaboratorPoolImport(unittest.TestCase):
    def test_payloads_module_binds_collab_pool(self):
        self.assertTrue(hasattr(_payloads, "_COLLAB_POOL"),
                        "_payloads must import _COLLAB_POOL or its tools NameError at call time")

    def test_shared_pool_is_the_same_object(self):
        # extend/pop in _payloads must mutate the list _oast exposes, not a copy.
        self.assertIs(_payloads._COLLAB_POOL, _oast._COLLAB_POOL)


if __name__ == "__main__":
    unittest.main()
