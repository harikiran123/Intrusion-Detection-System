from scapy.all import sniff, IP, TCP
import joblib
import numpy as np

model = joblib.load("ids_model.pkl")  # Ensure you have a trained model

def extract_features(packet):
    if IP in packet and TCP in packet:
        return [packet[IP].len, packet[TCP].sport, packet[TCP].dport, packet[TCP].flags]
    return None

def packet_handler(packet):
    features = extract_features(packet)
    if features:
        features = np.array(features).reshape(1, -1)
        prediction = model.predict(features)
        
        if prediction == 1:  
            print(f"[ALERT] Suspicious activity detected! {packet.summary()}")

print("Starting real-time network monitoring...")
sniff(prn=packet_handler, store=0, iface="eth0")
