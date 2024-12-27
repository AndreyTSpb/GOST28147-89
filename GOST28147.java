/**
 *
 * @author EnotPotaskun
 */
import java.util.Arrays;

public class GOST28147 {

    private static final int[][] S_BOX = {
            {4, 0xe, 5, 7, 6, 4, 0xd, 1},
            {0xa, 0xb, 8, 0xd, 0xc, 0xb, 0xb, 0xf},
            {9, 4, 1, 0xa, 7, 0xa, 4, 0xd},
            {2, 0xc, 0xd, 1, 1, 0, 1, 0},
            {0xd, 6, 0xa, 0, 5, 7, 3, 5},
            {8, 0xd, 3, 8, 0xf, 2, 0xf, 7},
            {0, 0xf, 4, 9, 0xd, 1, 5, 0xa},
            {0xe, 0xa, 2, 0xf, 8, 0xd, 9, 4},
            {6, 2, 0xe, 0xe, 4, 3, 0, 9},
            {0xb, 3, 0xf, 4, 0xa, 6, 0xa, 2},
            {1, 8, 0xc, 6, 9, 8, 0xe, 3},
            {0xc, 1, 7, 0xc, 0xe, 5, 7, 0xe},
            {7, 0, 6, 0xb, 0, 9, 6, 6},
            {0xf, 7, 0, 2, 3, 0xc, 8, 0xb},
            {5, 5, 9, 5, 0xb, 0xf, 2, 8},
            {3, 9, 0xb, 3, 2, 0xe, 0xc, 0xc}
    };

    private byte[] key;

    /**
     * Конструктор, проверяющий длину ключа.
     * @param key 
     */
    public GOST28147(byte[] key) {
        
        if (key.length != 32) {
            throw new IllegalArgumentException("Key must be 32 bytes long.");
        }
        this.key = key;
    }

    private int[] bytesToIntArray(byte[] bytes) {
        int[] ints = new int[bytes.length / 4];
        for(int i = 0; i < ints.length; i++){
            ints[i] = ((bytes[i*4] & 0xFF) << 24) |
                    ((bytes[i*4+1] & 0xFF) << 16) |
                    ((bytes[i*4+2] & 0xFF) << 8) |
                    (bytes[i*4+3] & 0xFF);
        }
        return ints;
    }

    private byte[] intArrayToBytes(int[] ints) {
        byte[] bytes = new byte[ints.length*4];
        for (int i = 0; i < ints.length; i++){
            bytes[i * 4] = (byte) ((ints[i] >> 24) & 0xFF);
            bytes[i * 4 + 1] = (byte) ((ints[i] >> 16) & 0xFF);
            bytes[i * 4 + 2] = (byte) ((ints[i] >> 8) & 0xFF);
            bytes[i * 4 + 3] = (byte) (ints[i] & 0xFF);
        }
        return bytes;
    }

    private int[] generateRoundKeys() {
       return bytesToIntArray(this.key);
    }


    /**
     * Заменяет 4-битные символы в S на основе S-Box
     * @param s
     * @return 
     */
    private int sBoxSubstitution(int s) {
        int result = 0;
        for (int i = 0; i < 8; i++) {
            int s_part = (s >> (i * 4)) & 0xF; // Извлекаем 4-битный символ
            result |= (S_BOX[s_part][i] << (i * 4)); // Заменяем и добавляем к результату
        }
        return result;
    }
    
    private int inverseSBoxSubstitution(int s) {
    int result = 0;
    for (int i = 0; i < 8; i++) {
        int s_part = (s >> (i * 4)) & 0xF; // Извлекаем 4-битный символ
        // Используем обратное значение из S_BOX
        result |= (S_BOX[s_part][i] >> (i * 4)); // Заменяем и добавляем к результату
    }
    return result;
}


    private int leftRotate(int value, int shift) {
        return (value << shift) | (value >>> (32 - shift));
    }
    
     /**
     * Вычисление (A + K) mod 2^32
     * @param A
     * @param K
     * @return 
     */
     public static int calculateS(int A, int K) {
          //В Java int является 32-битным знаковым целым числом
          //Сложение целых чисел (int) в Java автоматически переполняется, так как максимальное значение int это 2^31 - 1
          //Переполнение соответствует операции взятия по модулю 2^32.
          int sum = A + K;
          return sum;
     }
    
    private int[] getKeySchedule(int[] roundKeys){
        int[] keySchedule = new int[32]; //Этот массив содержит раундовые ключи в том порядке, в котором они должны быть использованы в 32 раундах шифрования
        for (int i = 0; i < 24; i++){
           // Прямой порядок для первых 24 раундов
           keySchedule[i] = roundKeys[i % 8];
        }
        for (int i = 24; i < 32; i++){
           // Обратный порядок для оставшихся 8 раундов
           keySchedule[i] = roundKeys[7- (i % 8)];
        }
        showHex(keySchedule);
        return keySchedule;
    }
    
    private int[]getReversKeyShedule(int[] roundKeys){
        int[] keySchedule = new int[32];
        // Прямой порядок для первых 8 раундов
        for (int i = 0; i < 8; i++) {
            keySchedule[i] = roundKeys[i % 8];
        }
        // Обратный порядок для оставшихся 24 раундов
        for (int i = 8; i < 32; i++) {
            keySchedule[i] = roundKeys[7 - (i % 8)];
        }
        showHex(keySchedule);
        return keySchedule;
    }
    
        /**
     * Шифрует один блок из 8 байтов
     * @param input
     * @param keySchedule
     * @return 
     */
    public byte[] encryptBlock(byte[] input, int[] keySchedule) {
        if (input.length != 8) {
            throw new IllegalArgumentException("Input must be 8 bytes long.");
        }
        
        //Дербаним на два блока
        int a = ((input[7] & 0xFF) << 24) |
                ((input[6] & 0xFF) << 16) |
                ((input[5] & 0xFF) << 8) |
                (input[4] & 0xFF); // Старшие 32 бита

        
        int b = ((input[3] & 0xFF) << 24) |
                ((input[2] & 0xFF) << 16) |
                ((input[1] & 0xFF) << 8) |
                (input[0] & 0xFF); // Младшие 32 бита
        /**
         * Шифруем блок А 
         */
        
        for (int i = 0; i < 32; i++) {
            //System.out.printf("A1 - %02x \n", a);
            //System.out.printf("B1 - %02x \n", b);
            
            int s = calculateS(a, keySchedule[i]);
            //System.out.printf("S - %02x \n", s);
            int s_substitution = sBoxSubstitution(s); //замена символов
            //System.out.printf("S_SUB_str %02x \n", s_substitution);
            int r = leftRotate(s_substitution, 11); //Смещение на 11
            //System.out.printf("R - %02x \n", r);
            int result = r ^ b; //XOR
            //System.out.printf("XOR - %02x \n", result);
            if(i < 31){
                b = a;
                a = result;
            }else{
                b = result;
            }
            //System.out.printf("A - %02x \n", a);
            //System.out.printf("B - %02x \n", b);
        }
        int[] result = {a,b};
        //showHex(result);
        //System.out.printf("res - %02x \n", result[0]+result[1]);
        return intArrayToBytes(result);
    }

    
    /**
     * Просмотр в шестнацатиричном формате массива
     * @param keySchedule 
     */
    private void showHex(int[] keySchedule){
        for (int i = 0; i < keySchedule.length; i++) {
            System.out.printf("K%d: %08x  ", i+1, keySchedule[i]);
           if ((i+1)%4 == 0){
               System.out.println();
           }
        }
        System.out.println();
    }
    
    /**
     * Реверс массива так как ключ должен быть К=(К8,К7,К6...К1)
     * @param array
     * @return 
     */
    private int[] reverse(int[] array) {
       int[] newArray = new int[array.length];

       for (int i = 0; i < array.length; i++) {
           newArray[array.length - 1 - i] = array[i];
       }

       return newArray;
    }
    
    
    
    public static void main(String[] args) {
        byte[] key = {
                0x73, 0x3d, 0x2c, 0x20, 0x65, 0x68, 0x65, 0x73,
                0x74, 0x74, 0x67, 0x69, 0x79, 0x67, 0x61, 0x20,
                0x62, 0x6e, 0x73, 0x73, 0x20, 0x65, 0x73, 0x69,
                0x32, 0x6c, 0x65, 0x68, 0x33, 0x20, 0x6d, 0x54
        };

        
        
        //K1: 33206d54  K2: 326c6568  K3: 20657369  K4: 626e7373  
        //K5: 79676120  K6: 74746769  K7: 65686573  K8: 733d2c20 
          
        byte[] plaintext = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        
        GOST28147 gost = new GOST28147(key);
        
        
        //Преобразуем клич в массив из 8 ключей по 8 байтов
        int[] roundKeys = gost.generateRoundKeys();
        roundKeys = gost.reverse(roundKeys); //делаем реверс массива
        //gost.showHex(roundKeys);
        
        //Вывод начального текста
        System.out.print("Plaintext: ");
        for(byte b : plaintext){
            System.out.printf("%02x ", b);
        }
        System.out.println();
        
        //получаем зашифрованный текст Ciphertext: 42 ab bc ce 32 bc 0b 1b 
        byte[] ciphertext = gost.encryptBlock(plaintext, gost.getKeySchedule(roundKeys));
        System.out.print("Ciphertext: ");
        for(byte b: ciphertext){
            System.out.printf("%02x ", b);
        }
        System.out.println();

        // Дешифруем текст
        byte[] decryptedText = gost.encryptBlock(ciphertext, gost.getReversKeyShedule(roundKeys));
        System.out.print("Decrypted Text: ");
        for(byte b: decryptedText){
            System.out.printf("%02x ", b);
        }
        System.out.println();
    }
}
