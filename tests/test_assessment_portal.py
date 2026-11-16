import unittest
from assessment_portal import make_plan, validate_docker_image

class GuidedAssessmentTests(unittest.TestCase):
    def test_lab_all_scanners(self):
        plan=make_plan('Running lab container','Juice Shop','Normal')
        self.assertEqual([s[1] for s in plan['scanner_plan']], ['Pending','Pending','Pending'])
        self.assertEqual(plan['zap_app'], 'OWASP Juice Shop')
    def test_image_only(self):
        plan=make_plan('Docker image','DVWA','Low')
        self.assertEqual([s[1] for s in plan['scanner_plan']], ['Pending','Skipped','Skipped'])
    def test_local_host(self):
        plan=make_plan('Local host','DVWA','High')
        self.assertEqual([s[1] for s in plan['scanner_plan']], ['Skipped','Pending','Skipped'])
    def test_custom_image(self):
        plan = make_plan('Docker image', 'Juice Shop', 'Normal', custom_image='python:3.11-slim')
        self.assertEqual(plan['image'], 'python:3.11-slim')
        self.assertEqual([s[1] for s in plan['scanner_plan']], ['Pending', 'Skipped', 'Skipped'])

    def test_custom_image_without_prior_lab_selection(self):
        plan = make_plan('Docker image', None, 'Normal', custom_image='python:3.11-slim')
        self.assertEqual(plan['image'], 'python:3.11-slim')
        self.assertEqual(plan['name'], 'python:3.11-slim')
        self.assertEqual([row[1] for row in plan['scanner_plan']], ['Pending', 'Skipped', 'Skipped'])

    def test_custom_image_invalid(self):
        for image in ('', '--help', 'python:3.11;echo', 'python image', '../etc/passwd'):
            with self.subTest(image=image), self.assertRaises(ValueError):
                validate_docker_image(image)

    def test_custom_image_only_for_docker_mode(self):
        with self.assertRaises(ValueError):
            make_plan('Local host', 'Juice Shop', 'Normal', custom_image='python:3.11-slim')

    def test_no_scanner_rejected(self):
        with self.assertRaises(ValueError): make_plan('Docker image','DVWA','Low',run_trivy=False)
    def test_untrusted_target_rejected(self):
        with self.assertRaises(ValueError): make_plan('Local host','external.example','High')
if __name__ == '__main__': unittest.main()
