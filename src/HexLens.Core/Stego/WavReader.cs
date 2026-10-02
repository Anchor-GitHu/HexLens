using HexLens.Core.Util;

namespace HexLens.Core.Stego;

/// <summary>
/// WAVE 音频读取：把 PCM 样本摊成"每字节一个通道"的样本网格，
/// 这样"16 位样本最低位"就等价于"通道 0 的位平面 0"，与图像 LSB 共用同一套提取器。
/// </summary>
public static class WavReader
{
    /// <summary>读取 WAV 的 PCM 样本。</summary>
    public static AudioSamples? Read(ReadOnlySpan<byte> data, int start, out string error)
    {
        error = string.Empty;
        if (start + 12 > data.Length) { error = "RIFF 头不完整"; return null; }
        if (ByteOrder.U32LE(data, start) != 0x46464952) { error = "起点不是 RIFF"; return null; }
        if (ByteOrder.U32LE(data, start + 8) != 0x45564157) { error = "不是 WAVE 表单"; return null; }

        int pos = start + 12;
        int format = 1, channels = 0, sampleRate = 0, bitsPerSample = 0;
        int dataOffset = -1, dataLength = 0;

        while (pos + 8 <= data.Length)
        {
            uint chunkSize = ByteOrder.U32LE(data, pos + 4);
            if (chunkSize > int.MaxValue) break;

            string id = System.Text.Encoding.ASCII.GetString(data.Slice(pos, 4));
            int body = pos + 8;
            int size = (int)chunkSize;

            if (id == "fmt " && body + 16 <= data.Length)
            {
                format = ByteOrder.U16LE(data, body);
                channels = ByteOrder.U16LE(data, body + 2);
                sampleRate = (int)ByteOrder.U32LE(data, body + 4);
                bitsPerSample = ByteOrder.U16LE(data, body + 14);
                if (format == 0xFFFE && body + 26 <= data.Length)
                    format = ByteOrder.U16LE(data, body + 24);   // WAVE_FORMAT_EXTENSIBLE 的子格式
            }
            else if (id == "data")
            {
                dataOffset = body;
                dataLength = Math.Min(size, data.Length - body);
                break;
            }

            pos = body + size + (size % 2);
        }

        if (dataOffset < 0) { error = "未找到 data 块"; return null; }
        if (channels <= 0) { error = "声道数非法"; return null; }
        if (bitsPerSample is not (8 or 16 or 24 or 32)) { error = $"不支持的位深 {bitsPerSample}"; return null; }

        int bytesPerSample = bitsPerSample / 8;
        int frameSize = channels * bytesPerSample;
        if (frameSize <= 0) { error = "帧大小非法"; return null; }

        int frames = dataLength / frameSize;
        int totalChannels = channels * bytesPerSample;

        var channelData = new byte[totalChannels][];
        for (int c = 0; c < totalChannels; c++) channelData[c] = new byte[frames];

        for (int f = 0; f < frames; f++)
        {
            int frameStart = dataOffset + f * frameSize;
            for (int ch = 0; ch < channels; ch++)
            {
                int sampleStart = frameStart + ch * bytesPerSample;
                for (int b = 0; b < bytesPerSample; b++)
                {
                    // 小端：b = 0 是低字节，放在通道 ch * bytesPerSample + b
                    channelData[ch * bytesPerSample + b][f] = data[sampleStart + b];
                }
            }
        }

        string describe = $"WAV {sampleRate} Hz，{channels} 声道，{bitsPerSample} 位，{frames} 帧";
        return new AudioSamples(frames, totalChannels, channelData, describe)
        {
            SampleRate = sampleRate,
            BitsPerSample = bitsPerSample,
        };
    }
}
