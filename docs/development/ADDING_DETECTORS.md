# Adding New Detectors

To add a new detector:

1. Create a class inheriting from `BaseDetector`.
2. Implement the `detect()` method.
3. Register it using `@register_detector`.
4. Write unit tests in `tests/detectors/`.
5. Document the detector in `docs/architecture/detector-system.md`.

Follow naming conventions and ensure your detector is categorized (Security or Performance).
