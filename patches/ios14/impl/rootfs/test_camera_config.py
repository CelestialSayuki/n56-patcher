import plistlib
import unittest

from patches.ios14.impl.rootfs.camera_config import convert


def session(*devices):
    return plistlib.dumps({"AVCaptureDevices": list(devices), "AVH264Settings": {}})


BACK = {"mediaType": "vide", "position": 1, "focusModes": [0, 1, 2, 3, 4],
        "MultiStream": {"AVCaptureSessionPresets": {"AVCaptureSessionPresetPhoto": {}}}}
FRONT = {"mediaType": "vide", "position": 2, "MultiStream": {}}
MICROPHONE = {"mediaType": "soun"}


class ConvertTest(unittest.TestCase):
    def test_back_camera_gains_auto_focus_and_keeps_formats(self):
        result = plistlib.loads(convert(session(BACK, FRONT, MICROPHONE)))
        back, front, microphone = result["AVCaptureDevices"]
        self.assertIs(back["hasAutoFocus"], True)
        self.assertEqual(back["MultiStream"], BACK["MultiStream"])
        self.assertNotIn("hasAutoFocus", front)
        self.assertEqual(microphone, MICROPHONE)
        self.assertEqual(result["AVH264Settings"], {})

    def test_fixed_focus_camera_is_left_alone(self):
        fixed = dict(BACK, focusModes=[0])
        result = plistlib.loads(convert(session(fixed)))
        self.assertNotIn("hasAutoFocus", result["AVCaptureDevices"][0])

    def test_camera_without_multistream_is_rejected(self):
        legacy = {"mediaType": "vide", "AVCaptureSessionPresetPhoto": {}}
        with self.assertRaises(ValueError):
            convert(session(legacy))

    def test_file_without_cameras_is_rejected(self):
        with self.assertRaises(ValueError):
            convert(session(MICROPHONE))


if __name__ == "__main__":
    unittest.main()
