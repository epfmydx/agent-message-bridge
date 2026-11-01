# Synthetic code-review exercise

This tiny example was authored for the documentation. It is not taken from a project.

```python
def unique_in_order(values):
    return sorted(set(values))
```

Required behavior: preserve first appearance of hashable inputs. For[3,1,3,2], expected[3,1,2]. The function instead returns[1,2,3]. One suitable correction for this stated input domain is `list(dict.fromkeys(values))`. The example makes no claim about unhashable inputs or production suitability.
