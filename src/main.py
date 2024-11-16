from ids import IntrusionDetectionSystem


class Main:
    def __init__(self):
        self.IntrusionDetectionSystem: IntrusionDetectionSystem = IntrusionDetectionSystem(20, 10)

    def start(self) -> None:
        self.IntrusionDetectionSystem.scan()


if __name__ == '__main__':
    Main().start()
