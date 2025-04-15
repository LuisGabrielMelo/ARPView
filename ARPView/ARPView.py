import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTableWidget,
    QTableWidgetItem, QMessageBox
)
from scapy.all import ARP, Ether, srp

class NetworkScanner(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Analizador de Red")
        self.setGeometry(300, 200, 600, 400)

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # Input y botón
        input_layout = QHBoxLayout()
        self.input_label = QLabel("Red objetivo:")
        self.input_field = QLineEdit()
        self.input_field.setPlaceholderText("Ej: 192.168.1.0/24")
        self.scan_button = QPushButton("Escanear")
        self.scan_button.clicked.connect(self.scan_network)

        input_layout.addWidget(self.input_label)
        input_layout.addWidget(self.input_field)
        input_layout.addWidget(self.scan_button)

        # Tabla de resultados
        self.result_table = QTableWidget()
        self.result_table.setColumnCount(2)
        self.result_table.setHorizontalHeaderLabels(["IP", "MAC"])
        self.result_table.setColumnWidth(0, 250)
        self.result_table.setColumnWidth(1, 300)

        layout.addLayout(input_layout)
        layout.addWidget(self.result_table)

        self.setLayout(layout)

    def scan_network(self):
        red_objetivo = self.input_field.text().strip()
        if not red_objetivo:
            QMessageBox.warning(self, "Error", "Por favor ingrese una red válida.")
            return

        self.result_table.setRowCount(0)

        try:
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp = ARP(pdst=red_objetivo)
            packet = ether / arp
            result = srp(packet, timeout=2, verbose=False)[0]

            for i, (sent, received) in enumerate(result):
                self.result_table.insertRow(i)
                self.result_table.setItem(i, 0, QTableWidgetItem(received.psrc))
                self.result_table.setItem(i, 1, QTableWidgetItem(received.hwsrc))

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Hubo un problema:\n{e}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    scanner = NetworkScanner()
    scanner.show()
    sys.exit(app.exec_())
