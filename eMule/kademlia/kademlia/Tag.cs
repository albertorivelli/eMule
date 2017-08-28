
using eMule;
using System.Diagnostics;

namespace Kademlia
{
    public interface ICloneable
    {
        object Clone();
    }

    public class KadTag : ICloneable
    {
        public byte m_type;
        public string m_name;

        public KadTag(byte type, string name)
        {
            m_type = type;
            m_name = name;
        }

        public virtual object Clone()
        {
            return new KadTag(m_type, m_name);
        }

        public bool IsStr()
        {
            return m_type == Opcodes.TAGTYPE_STRING;
        }

        public bool IsNum()
        {
            return m_type == Opcodes.TAGTYPE_UINT64 || m_type == Opcodes.TAGTYPE_UINT32 || m_type == Opcodes.TAGTYPE_UINT16 || m_type == Opcodes.TAGTYPE_UINT8 || m_type == Opcodes.TAGTYPE_BOOL || m_type == Opcodes.TAGTYPE_FLOAT32 || m_type == 0xFE;
        }

        public bool IsInt()
        {
            return m_type == Opcodes.TAGTYPE_UINT64 || m_type == Opcodes.TAGTYPE_UINT32 || m_type == Opcodes.TAGTYPE_UINT16 || m_type == Opcodes.TAGTYPE_UINT8 || m_type == 0xFE;
        }

        public bool IsFloat()
        {
            return m_type == Opcodes.TAGTYPE_FLOAT32;
        }

        public bool IsBsob()
        {
            return m_type == Opcodes.TAGTYPE_BSOB;
        }

        public bool IsHash()
        {
            return m_type == Opcodes.TAGTYPE_HASH;
        }

        public virtual string GetStr()
        {
            Debug.Assert(false);
            return "";
        }

        public virtual ulong GetInt()
        {
            Debug.Assert(false);
            return 0;
        }

        public virtual float GetFloat()
        {
            Debug.Assert(false);
            return 0.0F;
        }

        public virtual byte[] GetBsob()
        {
            Debug.Assert(false);
            return null;
        }

        public virtual byte GetBsobSize()
        {
            Debug.Assert(false);
            return 0;
        }

        public virtual bool GetBool()
        {
            Debug.Assert(false);
            return false;
        }

        public virtual byte[] GetHash()
        {
            Debug.Assert(false);
            return null;
        }
    }

    public class KadTagUnk : KadTag
    {
        public KadTagUnk(byte type, string name) : base(type, name)
        {
        }

        public override object Clone()
        {
            return new KadTagUnk(m_type, m_name);
        }
    }

    public class KadTagStr : KadTag
    {
    protected string m_value;

        public KadTagStr(string name, string value, int len)
                    : base(Opcodes.TAGTYPE_STRING, name)
        {
            m_value = value;
        }

        public KadTagStr(string name, string rstr)
                    : base(Opcodes.TAGTYPE_STRING, name)
        {
            m_value = rstr;
        }

        public override object Clone()
        {
            return new KadTagStr("","");
        }

        public override string GetStr()
        {
            return m_value;
        }
    }

    //class CKadTagUInt : public CKadTag
    //{
    //	public:
    //		CKadTagUInt(LPCSTR name, uint64 value)
    //				: CKadTag(0xFE, name)
    //				, m_value(value)
    //		{ }

    //		virtual CKadTagUInt* Copy()
    //		{
    //			return new CKadTagUInt(*this);
    //		}

    //		virtual uint64 GetInt() const
    //		{
    //			return m_value;
    //		}

    //	protected:
    //		uint64 m_value;
    //};

    //class CKadTagUInt64 : public CKadTag
    //{
    //	public:
    //		CKadTagUInt64(LPCSTR name, uint64 value)
    //				: CKadTag(TAGTYPE_UINT64, name)
    //				, m_value(value)
    //		{ }

    //		virtual CKadTagUInt64* Copy()
    //		{
    //			return new CKadTagUInt64(*this);
    //		}

    //		virtual uint64 GetInt() const
    //		{
    //			return m_value;
    //		}

    //	protected:
    //		uint64 m_value;
    //};

    //class CKadTagUInt32 : public CKadTag
    //{
    //	public:
    //		CKadTagUInt32(LPCSTR name, uint32 value)
    //				: CKadTag(TAGTYPE_UINT32, name)
    //				, m_value(value)
    //		{ }

    //		virtual CKadTagUInt32* Copy()
    //		{
    //			return new CKadTagUInt32(*this);
    //		}

    //		virtual uint64 GetInt() const
    //		{
    //			return m_value;
    //		}

    //	protected:
    //		uint32 m_value;
    //};


    //class CKadTagFloat : public CKadTag
    //{
    //	public:
    //		CKadTagFloat(LPCSTR name, float value)
    //				: CKadTag(TAGTYPE_FLOAT32, name)
    //				, m_value(value)
    //		{ }

    //		virtual CKadTagFloat* Copy()
    //		{
    //			return new CKadTagFloat(*this);
    //		}

    //		virtual float GetFloat() const
    //		{
    //			return m_value;
    //		}

    //	protected:
    //		float m_value;
    //};


    //class CKadTagBool : public CKadTag
    //{
    //	public:
    //		CKadTagBool(LPCSTR name, bool value)
    //				: CKadTag(TAGTYPE_BOOL, name)
    //				, m_value(value)
    //		{ }

    //		virtual CKadTagBool* Copy()
    //		{
    //			return new CKadTagBool(*this);
    //		}

    //		virtual bool GetBool() const
    //		{
    //			return m_value;
    //		}

    //	protected:
    //		bool m_value;
    //};


    //class CKadTagUInt16 : public CKadTag
    //{
    //	public:
    //		CKadTagUInt16(LPCSTR name, uint16 value)
    //				: CKadTag(TAGTYPE_UINT16, name)
    //				, m_value(value)
    //		{ }

    //		virtual CKadTagUInt16* Copy()
    //		{
    //			return new CKadTagUInt16(*this);
    //		}

    //		virtual uint64 GetInt() const
    //		{
    //			return m_value;
    //		}

    //	protected:
    //		uint16 m_value;
    //};


    //class CKadTagUInt8 : public CKadTag
    //{
    //	public:
    //		CKadTagUInt8(LPCSTR name, uint8 value)
    //				: CKadTag(TAGTYPE_UINT8, name)
    //				, m_value(value)
    //		{ }

    //		virtual CKadTagUInt8* Copy()
    //		{
    //			return new CKadTagUInt8(*this);
    //		}

    //		virtual uint64 GetInt() const
    //		{
    //			return m_value;
    //		}

    //	protected:
    //		uint8 m_value;
    //};


    //class CKadTagBsob : public CKadTag
    //{
    //	public:
    //		CKadTagBsob(LPCSTR name, const BYTE* value, uint8 nSize)
    //				: CKadTag(TAGTYPE_BSOB, name)
    //		{
    //			m_value = new BYTE[nSize];
    //			memcpy(m_value, value, nSize);
    //			m_size = nSize;
    //		}
    //		CKadTagBsob(const CKadTagBsob& rTag)
    //				: CKadTag(rTag)
    //		{
    //			m_value = new BYTE[rTag.m_size];
    //			memcpy(m_value, rTag.m_value, rTag.m_size);
    //			m_size = rTag.m_size;
    //		}
    //		~CKadTagBsob()
    //		{
    //			delete[] m_value;
    //		}

    //		virtual CKadTagBsob* Copy()
    //		{
    //			return new CKadTagBsob(*this);
    //		}

    //		virtual const BYTE* GetBsob() const
    //		{
    //			return m_value;
    //		}
    //		virtual uint8 GetBsobSize() const
    //		{
    //			return m_size;
    //		}

    //	protected:
    //		BYTE* m_value;
    //		uint8 m_size;
    //};


    //class CKadTagHash : public CKadTag
    //{
    //	public:
    //		CKadTagHash(LPCSTR name, const BYTE* value)
    //				: CKadTag(TAGTYPE_HASH, name)
    //		{
    //			m_value = new BYTE[16];
    //			md4cpy(m_value, value);
    //		}
    //		CKadTagHash(const CKadTagHash& rTag)
    //				: CKadTag(rTag)
    //		{
    //			m_value = new BYTE[16];
    //			md4cpy(m_value, rTag.m_value);
    //		}
    //		~CKadTagHash()
    //		{
    //			delete[] m_value;
    //		}

    //		virtual CKadTagHash* Copy()
    //		{
    //			return new CKadTagHash(*this);
    //		}

    //		virtual const BYTE* GetHash() const
    //		{
    //			return m_value;
    //		}

    //	protected:
    //		BYTE* m_value;
    //};
}
