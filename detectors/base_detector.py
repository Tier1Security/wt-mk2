# detectors/base_detector.py

class BaseDetector:
    """
    Base class for all high-level attack detectors.
    Subclasses must implement `on_event()` and call `self.alert_callback()`
    when they detect an attack.
    """

    def __init__(self, config: dict, alert_callback):
        """
        Args:
          config (dict): YAML-loaded configuration for this detector.
          alert_callback (callable): function(alert_dict) to invoke on detection.
        """
        self.config = config
        self.alert_callback = alert_callback

    def on_event(self, event: dict):
        """
        Consume a normalized event; must be overridden by subclasses.
        """
        raise NotImplementedError("Subclasses must implement on_event()")
