import axios from 'axios';

const API_BASE_URL = 'http://localhost:8000/api';

export const scannerApi = {
  startScan: async (url: string) => {
    try {
      const response = await axios.post(`${API_BASE_URL}/start-scan/`, { url });
      return response.data;
    } catch (error) {
      console.error('Error starting scan:', error);
      throw error;
    }
  },
  
  getScanStatus: async (scanId: string | number) => {
    try {
      const response = await axios.get(`${API_BASE_URL}/scan-status/${scanId}/`);
      return response.data;
    } catch (error) {
      console.error('Error getting scan status:', error);
      throw error;
    }
  }
};