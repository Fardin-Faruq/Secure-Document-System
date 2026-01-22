import axios from 'axios';

const API_URL = 'http://localhost:5000/api';

export const testConnection = async () => {
    try {
        const response = await axios.get(`${API_URL}/test`);
        return response.data;
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
};