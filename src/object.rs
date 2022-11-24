use ascii::{AsciiString};
use nom::{error::ParseError, IResult, number::complete::{le_u8, le_u32, le_u16}, multi::count};

pub struct Header {
  pub id: HeaderID,
  pub value: HeaderValue,
}

impl Header {
  /// Attempts to parse a `Header` from a `&[u8]`
  ///
  /// # Examples
  ///
  /// Count
  /// ```
  /// # use obex::object::Header;
  /// # use obex::object::HeaderID;
  /// # use obex::object::HeaderValue;
  /// // Little Endian encoded 4 byte integer byte sequence
  /// let data: [u8; 5] = [0xC0, 0, 0, 0, 0];
  /// let (data, header) = Header::parse(&data).unwrap();
  ///
  /// assert_eq!(HeaderID::Count, header.id);
  /// assert_eq!(HeaderValue::Count(0), header.value);
  /// ```
  ///
  /// Name
  /// ```
  /// # use obex::object::Header;
  /// # use obex::object::HeaderID;
  /// # use obex::object::HeaderValue;
  /// // Little Endian encoded UTF-8 null terminated byte sequence
  /// let data: [u8; 8] = [0x01, 5, 0, 116, 101, 120, 116, 0];
  /// let (data, header) = Header::parse(&data).unwrap();
  ///
  /// assert_eq!(HeaderID::Name, header.id);
  /// assert_eq!(HeaderValue::Name("text\0".to_string()), header.value);
  /// ```
  ///
  /// Type
  /// ```
  /// # use obex::object::Header;
  /// # use obex::object::HeaderID;
  /// # use obex::object::HeaderValue;
  /// # use ascii::{AsAsciiStr, AsciiChar};
  /// // Little Endian encoded ASCII null terminated byte sequence
  /// let data: [u8; 7] = [0x42, 4, 0, 112, 100, 102, 0];
  /// let (data, header) = Header::parse(&data).unwrap();
  ///
  /// assert_eq!(HeaderID::Type, header.id);
  /// assert_eq!(HeaderValue::Type("pdf\0".as_ascii_str().unwrap().to_ascii_string()), header.value);
  /// ```
  ///
  /// Length
  /// ```
  /// # use obex::object::Header;
  /// # use obex::object::HeaderID;
  /// # use obex::object::HeaderValue;
  /// // Little Endian encoded 4 byte integer byte sequence
  /// let data: [u8; 5] = [0xC3, 1, 0, 0, 0];
  /// let (data, header) = Header::parse(&data).unwrap();
  ///
  /// assert_eq!(HeaderID::Length, header.id);
  /// assert_eq!(HeaderValue::Length(1), header.value);
  /// ```
  ///
  /// Time
  /// ```
  /// # use obex::object::Header;
  /// # use obex::object::HeaderID;
  /// # use obex::object::HeaderValue;
  /// # use ascii::{AsAsciiStr, AsciiChar};
  /// // Little Endian encoded encoded ASCII byte sequence ISO 8601 Formatted
  /// let data: [u8; 19] = [0x44, 16, 0, 49, 57, 57, 52, 48, 50, 48, 54, 84, 48, 49, 48, 49, 48, 49, 90];
  /// let (data, header) = Header::parse(&data).unwrap();
  ///
  /// assert_eq!(HeaderID::Time, header.id);
  /// assert_eq!(HeaderValue::Time("19940206T010101Z".as_ascii_str().unwrap().to_ascii_string()), header.value)
  /// ```
  ///
  /// Description
  /// ```
  /// # use obex::object::Header;
  /// # use obex::object::HeaderID;
  /// # use obex::object::HeaderValue;
  /// // Little Endian encoded UTF-8 null terminated byte sequence
  /// let data: [u8; 8] = [0x05, 5, 0, 116, 101, 120, 116, 0];
  /// let (data, header) = Header::parse(&data).unwrap();
  ///
  /// assert_eq!(HeaderID::Description, header.id);
  /// assert_eq!(HeaderValue::Description("text\0".to_string()), header.value);
  /// ```
  ///
  /// Target
  /// ```
  /// # use obex::object::Header;
  /// # use obex::object::HeaderID;
  /// # use obex::object::HeaderValue;
  /// // Little Endian encoded length prefixed byte array
  /// let data: [u8; 8] = [0x46, 5, 0, 1, 2, 3, 4, 5];
  /// let (data, header) = Header::parse(&data).unwrap();
  ///
  /// let expected = Vec::from([1, 2, 3, 4, 5]);
  ///
  /// assert_eq!(HeaderID::Target, header.id);
  /// assert_eq!(HeaderValue::Target(expected), header.value);
  /// ```
  ///
  /// HTTP
  /// ```
  /// # use obex::object::Header;
  /// # use obex::object::HeaderID;
  /// # use obex::object::HeaderValue;
  /// // Little Endian encoded length prefixed byte array
  /// let data: [u8; 8] = [0x47, 5, 0, 1, 2, 3, 4, 5];
  /// let (data, header) = Header::parse(&data).unwrap();
  ///
  /// let expected = Vec::from([1, 2, 3, 4, 5]);
  ///
  /// assert_eq!(HeaderID::HTTP, header.id);
  /// assert_eq!(HeaderValue::HTTP(expected), header.value);
  /// ```
  ///
  /// Body
  /// ```
  /// # use obex::object::Header;
  /// # use obex::object::HeaderID;
  /// # use obex::object::HeaderValue;
  /// // Little Endian encoded length prefixed byte array
  /// let data: [u8; 8] = [0x48, 5, 0, 1, 2, 3, 4, 5];
  /// let (data, header) = Header::parse(&data).unwrap();
  ///
  /// let expected = Vec::from([1, 2, 3, 4, 5]);
  ///
  /// assert_eq!(HeaderID::Body, header.id);
  /// assert_eq!(HeaderValue::Body(expected), header.value);
  /// ```
  ///
  /// EndOfBody
  /// ```
  /// # use obex::object::Header;
  /// # use obex::object::HeaderID;
  /// # use obex::object::HeaderValue;
  /// // Little Endian encoded length prefixed byte array
  /// let data: [u8; 8] = [0x49, 5, 0, 1, 2, 3, 4, 5];
  /// let (data, header) = Header::parse(&data).unwrap();
  ///
  /// let expected = Some(Vec::from([1, 2, 3, 4, 5]));
  ///
  /// assert_eq!(HeaderID::EndOfBody, header.id);
  /// assert_eq!(HeaderValue::EndOfBody(expected), header.value);
  /// ```
  ///
  /// Who
  /// ```
  /// # use obex::object::Header;
  /// # use obex::object::HeaderID;
  /// # use obex::object::HeaderValue;
  /// // Little Endian encoded length prefixed byte array
  /// let data: [u8; 8] = [0x4A, 5, 0, 1, 2, 3, 4, 5];
  /// let (data, header) = Header::parse(&data).unwrap();
  ///
  /// let expected = Vec::from([1, 2, 3, 4, 5]);
  ///
  /// assert_eq!(HeaderID::Who, header.id);
  /// assert_eq!(HeaderValue::Who(expected), header.value);
  /// ```
  ///
  /// ConnectionID
  /// ```
  /// # use obex::object::Header;
  /// # use obex::object::HeaderID;
  /// # use obex::object::HeaderValue;
  /// // Little Endian encoded 4 byte integer byte sequence
  /// let data: [u8; 5] = [0xCB, 15, 0, 0, 0];
  /// let (data, header) = Header::parse(&data).unwrap();
  ///
  /// assert_eq!(HeaderID::ConnectionID, header.id);
  /// assert_eq!(HeaderValue::ConnectionID([15, 0, 0, 0]), header.value);
  /// ```
  ///
  /// CreatorID
  /// ```
  /// # use obex::object::Header;
  /// # use obex::object::HeaderID;
  /// # use obex::object::HeaderValue;
  /// // Little Endian encoded 4 byte integer byte sequence
  /// let data: [u8; 5] = [0xCF, 15, 0, 0, 0];
  /// let (data, header) = Header::parse(&data).unwrap();
  ///
  /// assert_eq!(HeaderID::CreatorID, header.id);
  /// assert_eq!(HeaderValue::CreatorID(15), header.value);
  /// ```
  ///
  /// WANUUID
  /// ```
  /// # use obex::object::Header;
  /// # use obex::object::HeaderID;
  /// # use obex::object::HeaderValue;
  /// // Little Endian encoded 16 byte UUID
  /// let data: [u8; 17] = [0x50, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 ,16];
  /// let (data, header) = Header::parse(&data).unwrap();
  ///
  /// assert_eq!(HeaderID::WANUUID, header.id);
  /// assert_eq!(HeaderValue::WANUUID([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 ,16]), header.value);
  /// ```
  ///
  /// ObjectClass
  /// ```
  /// # use obex::object::Header;
  /// # use obex::object::HeaderID;
  /// # use obex::object::HeaderValue;
  /// // Little Endian encoded 16 byte UUID
  /// let data: [u8; 8] = [0x51, 5, 0, 1, 2, 3, 4, 5];
  /// let (data, header) = Header::parse(&data).unwrap();
  ///
  /// let expected = Vec::from([1, 2, 3, 4, 5]);
  ///
  /// assert_eq!(HeaderID::ObjectClass, header.id);
  /// assert_eq!(HeaderValue::ObjectClass(expected), header.value);
  /// ```
  ///
  /// SessionSequenceNumber
  /// ```
  /// # use obex::object::Header;
  /// # use obex::object::HeaderID;
  /// # use obex::object::HeaderValue;
  /// // Little Endian encoded 16 byte UUID
  /// let data: [u8; 2] = [0x93, 11];
  /// let (data, header) = Header::parse(&data).unwrap();
  ///
  /// assert_eq!(HeaderID::SessionSequenceNumber, header.id);
  /// assert_eq!(HeaderValue::SessionSequenceNumber(11), header.value);
  /// ```
  ///
  /// ActionID
  /// ```
  /// # use obex::object::Header;
  /// # use obex::object::HeaderID;
  /// # use obex::object::HeaderValue;
  /// // Little Endian encoded 16 byte UUID
  /// let data: [u8; 2] = [0x94, 11];
  /// let (data, header) = Header::parse(&data).unwrap();
  ///
  /// assert_eq!(HeaderID::ActionID, header.id);
  /// assert_eq!(HeaderValue::ActionID(11), header.value);
  /// ```
  ///
  /// DestName
  /// ```
  /// # use obex::object::Header;
  /// # use obex::object::HeaderID;
  /// # use obex::object::HeaderValue;
  /// // Little Endian encoded UTF-8 null terminated byte sequence
  /// let data: [u8; 8] = [0x15, 5, 0, 116, 101, 120, 116, 0];
  /// let (data, header) = Header::parse(&data).unwrap();
  ///
  /// assert_eq!(HeaderID::DestName, header.id);
  /// assert_eq!(HeaderValue::DestName("text\0".to_string()), header.value);
  /// ```
  ///
  /// Permissions
  /// ```
  /// # use obex::object::Header;
  /// # use obex::object::HeaderID;
  /// # use obex::object::HeaderValue;
  /// // Little Endian encoded
  /// let data: [u8; 5] = [0xD6, 5, 0, 0, 0];
  /// let (data, header) = Header::parse(&data).unwrap();
  ///
  /// assert_eq!(HeaderID::Permissions, header.id);
  /// assert_eq!(HeaderValue::Permissions(5), header.value);
  /// ```
  ///
  /// SingleResponseMode
  /// ```
  /// # use obex::object::Header;
  /// # use obex::object::HeaderID;
  /// # use obex::object::HeaderValue;
  /// // Little Endian encoded u8 byte
  /// let data: [u8; 2] = [0x97, 1];
  /// let (data, header) = Header::parse(&data).unwrap();
  ///
  /// assert_eq!(HeaderID::SingleResponseMode, header.id);
  /// assert_eq!(HeaderValue::SingleResponseMode(1), header.value);
  /// ```
  ///
  /// SingleResponseModeParameters
  /// ```
  /// # use obex::object::Header;
  /// # use obex::object::HeaderID;
  /// # use obex::object::HeaderValue;
  /// // Little Endian encoded u8 byte
  /// let data: [u8; 2] = [0x98, 1];
  /// let (data, header) = Header::parse(&data).unwrap();
  ///
  /// assert_eq!(HeaderID::SingleResponseModeParameters, header.id);
  /// assert_eq!(HeaderValue::SingleResponseModeParameters(1), header.value);
  /// ```
  pub fn parse(i: &[u8]) -> IResult<&[u8], Header> {
    let (i, id) = HeaderID::parse(i)?;

    match id {
      HeaderID::Count => {
        let (i, value) = le_u32(i)?;

        let header = Header {
          id: id,
          value: HeaderValue::Count(value)
        };

        Ok((i, header))
      },
      HeaderID::Name => {
        let (i, length) = le_u16(i)?;
        let (i, value) = count(le_u8, length.into())(i)?;

        let header: Header = Header {
          id: id,
          value: HeaderValue::Name(String::from_utf8(value).unwrap())
        };

        Ok((i, header))
      },
      HeaderID::Type => {
        let (i, length) = le_u16(i)?;
        let (i, value) = count(le_u8, length.into())(i)?;

        let header: Header = Header {
          id: id,
          value: HeaderValue::Type(AsciiString::from_ascii(value).unwrap())
        };

        Ok((i, header))
      },
      HeaderID::Length => {
        let (i, length) = le_u32(i)?;

        let header = Header {
          id: id,
          value: HeaderValue::Length(length)
        };

        Ok((i, header))
      },
      HeaderID::Time => {
        let (i, length) = le_u16(i)?;
        let (i, value) = count(le_u8, length.into())(i)?;

        let header: Header = Header {
          id: id,
          value: HeaderValue::Time(AsciiString::from_ascii(value).unwrap())
        };

        Ok((i, header))
      },
      HeaderID::Description => {
        let (i, length) = le_u16(i)?;
        let (i, value) = count(le_u8, length.into())(i)?;

        let header: Header = Header {
          id: id,
          value: HeaderValue::Description(String::from_utf8(value).unwrap())
        };

        Ok((i, header))
      },
      HeaderID::Target => {
        let (i, length) = le_u16(i)?;
        let (i, value) = count(le_u8, length.into())(i)?;

        let header: Header = Header {
          id: id,
          value: HeaderValue::Target(value)
        };

        Ok((i, header))
      },
      HeaderID::HTTP => {
        let (i, length) = le_u16(i)?;
        let (i, value) = count(le_u8, length.into())(i)?;

        let header: Header = Header {
          id: id,
          value: HeaderValue::HTTP(value)
        };

        Ok((i, header))
      },
      HeaderID::Body => {
        let (i, length) = le_u16(i)?;
        let (i, value) = count(le_u8, length.into())(i)?;

        let header: Header = Header {
          id: id,
          value: HeaderValue::Body(value)
        };

        Ok((i, header))
      },
      HeaderID::EndOfBody => {
        let (i, length) = le_u16(i)?;
        let (i, value) = count(le_u8, length.into())(i)?;

        let header: Header = Header {
          id: id,
          value: HeaderValue::EndOfBody(Some(value))
        };

        Ok((i, header))
      },
      HeaderID::Who => {
        let (i, length) = le_u16(i)?;
        let (i, value) = count(le_u8, length.into())(i)?;

        let header: Header = Header {
          id: id,
          value: HeaderValue::Who(value)
        };

        Ok((i, header))
      },
      HeaderID::ConnectionID => {
        let (i, value) = count(le_u8, 4)(i)?;

        let slice = value.as_slice();

        // TODO: This logic may be incorrect I doubt we want to panic here in reality.
        let array: [u8; 4] = match slice.try_into() {
          Ok(value) => value,
          Err(_) => panic!("Expected a vec of length {} but it was {}", 4, value.len())
        };

        let header: Header = Header {
          id: id,
          value: HeaderValue::ConnectionID(array)
        };

        Ok((i, header))
      },
      // TODO: Implement ApplicationParameters
      HeaderID::ApplicationParameters => {
        panic!("ApplicationParameters Unimplemented");
      },
      // TODO: Implement AuthenticateChallenge
      HeaderID::AuthenticateChallenge => {
        panic!("AuthenticateChallenge Unimplemented");
      },
      // TODO: Implement AuthenticateResponse
      HeaderID::AuthenticateResponse => {
        panic!("AuthenticateResponse Unimplemented");
      },
      HeaderID::CreatorID => {
        let (i, value) = le_u32(i)?;

        let header: Header = Header {
          id: id,
          value: HeaderValue::CreatorID(value)
        };

        Ok((i, header))
      },
      HeaderID::WANUUID => {
        let (i, value) = count(le_u8, 16)(i)?;

        let slice = value.as_slice();

        // TODO: This logic may be incorrect I doubt we want to panic here in reality.
        let array: [u8; 16] = match slice.try_into() {
          Ok(value) => value,
          Err(_) => panic!("Expected a vec of length {} but it was {}", 16, value.len())
        };

        let header: Header = Header {
          id: id,
          value: HeaderValue::WANUUID(array)
        };

        Ok((i, header))
      },
      HeaderID::ObjectClass => {
        let (i, length) = le_u16(i)?;
        let (i, value) = count(le_u8, length.into())(i)?;

        let header: Header = Header {
          id: id,
          value: HeaderValue::ObjectClass(value)
        };

        Ok((i, header))
      },
      // TODO: Implement SessionParameters
      HeaderID::SessionParameters => {
        panic!("SessionParameters Unimplemented");
      },
      HeaderID::SessionSequenceNumber => {
        let (i, value) = le_u8(i)?;

        let header: Header = Header {
          id: id,
          value: HeaderValue::SessionSequenceNumber(value)
        };

        Ok((i, header))
      },
      HeaderID::ActionID => {
        let (i, value) = le_u8(i)?;

        let header: Header = Header {
          id: id,
          value: HeaderValue::ActionID(value)
        };

        Ok((i, header))
      },
      HeaderID::DestName => {
        let (i, length) = le_u16(i)?;
        let (i, value) = count(le_u8, length.into())(i)?;

        let header: Header = Header {
          id: id,
          value: HeaderValue::DestName(String::from_utf8(value).unwrap())
        };

        Ok((i, header))
      },
      HeaderID::Permissions => {
        let (i, value) = le_u32(i)?;

        let header: Header = Header {
          id: id,
          value: HeaderValue::Permissions(value)
        };

        Ok((i, header))
      },
      HeaderID::SingleResponseMode => {
        let (i, value) = le_u8(i)?;

        let header: Header = Header {
          id: id,
          value: HeaderValue::SingleResponseMode(value)
        };

        Ok((i, header))
      },
      HeaderID::SingleResponseModeParameters => {
        let (i, value) = le_u8(i)?;

        let header: Header = Header {
          id: id,
          value: HeaderValue::SingleResponseModeParameters(value)
        };

        Ok((i, header))
      },
    }
  }

}

impl From<Header> for Vec<u8> {
  fn from(header: Header) -> Vec<u8> {
    let id: u8 = header.id.into();
    let value: Vec<u8> = header.value.into();

    let mut bytes: Vec<u8> = Vec::new();
    bytes.push(id);
    bytes.extend(value);

    return bytes;
  }
}

#[derive(Debug, PartialEq, Clone)]
pub enum HeaderValue {
  Count(u32),
  Name(String), // TODO: Is null terminated but rust does not use null terminated UTF-8
  Type(AsciiString),
  Length(u32),
  Time(AsciiString), // TODO: Should be formatted ISO time not just some string
  Description(String), // TODO: Is null terminated but rust does not use null terminated UTF-8
  Target(Vec<u8>),
  HTTP(Vec<u8>),
  Body(Vec<u8>), // TODO: This may be wrong no idea if it's actually a Vec of U8 but probably is.
  EndOfBody(Option<Vec<u8>>), // TODO: This may be wrong as it can be a null or empty header or contain value but no clue?
  Who(Vec<u8>),
  ConnectionID([u8; 4]),
  ApplicationParameters(), // TODO: Implement Obex TLV Parsing
  AuthenticateChallenge(), // TODO: Implement Obex TLV Parsing
  AuthenticateResponse(), // TODO: Implement Obex TLV Parsing
  CreatorID(u32),
  WANUUID([u8; 16]),
  ObjectClass(Vec<u8>), // TODO: Unsure of if sub types need to be implemented here.
  SessionParameters(), // TODO: Implement Obex TLV Parsing
  SessionSequenceNumber(u8),
  ActionID(u8),
  DestName(String), // TODO: Is null terminated but rust does not null terminate UTF-8
  Permissions(u32),
  SingleResponseMode(u8),
  SingleResponseModeParameters(u8)
}

impl From<HeaderValue> for Vec<u8> {
  /// Attempts to convert a `HeaderValue` to `Vec<u8>`
  ///
  /// # Examples
  ///
  /// Count
  /// ```
  /// #
  /// # use obex::object::HeaderValue;
  ///
  /// // Little Endian encoded 32 bit representation of 2.
  /// let mut expected = Vec::from([2,0,0,0]);
  ///
  /// let value =  HeaderValue::Count(2);
  /// let bytes: Vec<u8> = value.into();
  ///
  /// assert_eq!(expected, bytes);
  /// ```
  ///
  /// Name
  /// ```
  /// #
  /// # use obex::object::HeaderValue;
  ///
  /// // UTF-8 Byte representation of the word "test"
  /// let mut expected = Vec::from([0x74,0x65,0x73,0x74]);
  ///
  /// let value =  HeaderValue::Name("test".to_string());
  /// let bytes: Vec<u8> = value.into();
  ///
  /// assert_eq!(expected, bytes);
  /// ```
  ///
  /// Type
  /// ```
  /// #
  /// # use obex::object::HeaderValue;
  /// # use ascii::{AsciiString};
  ///
  /// // ASCII Byte representation of the word "test"
  /// let mut expected = Vec::from([116, 101, 115, 116]);
  ///
  /// let value = HeaderValue::Type(AsciiString::from_ascii("test").unwrap());
  /// let bytes: Vec<u8> = value.into();
  ///
  /// assert_eq!(expected, bytes);
  /// ```
  ///
  /// Length
  /// ```
  /// #
  /// # use obex::object::HeaderValue;
  ///
  /// // Little Endian Encoded 4 Byte representation of '2'
  /// let mut expected = Vec::from([2,0,0,0]);
  ///
  /// let value = HeaderValue::Length(2);
  /// let bytes: Vec<u8> = value.into();
  ///
  /// assert_eq!(expected, bytes);
  /// ```
  ///
  /// Time
  /// ```
  /// #
  /// # use obex::object::HeaderValue;
  /// # use ascii::{AsciiString};
  ///
  /// // ASCII Byte representation of an  ISO 8601 DateTime "19940206T010101Z"
  /// let mut expected = Vec::from([49, 57, 57, 52, 48, 50, 48, 54, 84, 48, 49, 48, 49, 48, 49, 90]);
  ///
  /// let value = HeaderValue::Time(AsciiString::from_ascii("19940206T010101Z").unwrap());
  /// let bytes: Vec<u8> = value.into();
  ///
  /// assert_eq!(expected, bytes);
  /// ```
  ///
  /// Description
  /// ```
  /// #
  /// # use obex::object::HeaderValue;
  ///
  /// // UTF-8 Byte representation of the word "test"
  /// let mut expected = Vec::from([0x74,0x65,0x73,0x74]);
  ///
  /// let value =  HeaderValue::Description("test".to_string());
  /// let bytes: Vec<u8> = value.into();
  ///
  /// assert_eq!(expected, bytes);
  /// ```
  ///
  /// Target
  /// ```
  /// #
  /// # use obex::object::HeaderValue;
  ///
  /// // UTF-8 Byte representation of the word "test"
  /// let expected = Vec::from([0x74,0x65,0x73,0x74]);
  ///
  /// let value =  HeaderValue::Target(expected.clone());
  /// let bytes: Vec<u8> = value.into();
  ///
  /// assert_eq!(expected, bytes);
  /// ```
  ///
  /// HTTP
  /// ```
  /// #
  /// # use obex::object::HeaderValue;
  ///
  /// // UTF-8 Byte representation of the word "test"
  /// let expected = Vec::from([0x74,0x65,0x73,0x74]);
  ///
  /// let value =  HeaderValue::HTTP(expected.clone());
  /// let bytes: Vec<u8> = value.into();
  ///
  /// assert_eq!(expected, bytes);
  /// ```
  ///
  /// Body
  /// ```
  /// #
  /// # use obex::object::HeaderValue;
  ///
  /// // UTF-8 Byte representation of the word "test"
  /// let expected = Vec::from([0x74,0x65,0x73,0x74]);
  ///
  /// let value =  HeaderValue::Body(expected.clone());
  /// let bytes: Vec<u8> = value.into();
  ///
  /// assert_eq!(expected, bytes);
  /// ```
  ///
  /// EndOfBody
  /// ```
  /// #
  /// # use obex::object::HeaderValue;
  ///
  /// // UTF-8 Byte representation of the word "test"
  /// let expected = Vec::from([0x74,0x65,0x73,0x74]);
  ///
  /// let value =  HeaderValue::EndOfBody(Some(expected.clone()));
  /// let bytes: Vec<u8> = value.into();
  ///
  /// assert_eq!(expected, bytes);
  /// ```
  ///
  /// Who
  /// ```
  /// #
  /// # use obex::object::HeaderValue;
  ///
  /// // UTF-8 Byte representation of the word "test"
  /// let expected = Vec::from([0x74,0x65,0x73,0x74]);
  ///
  /// let value =  HeaderValue::Who(expected.clone());
  /// let bytes: Vec<u8> = value.into();
  ///
  /// assert_eq!(expected, bytes);
  /// ```
  ///
  /// ConnectionID
  /// ```
  /// #
  /// # use obex::object::HeaderValue;
  ///
  /// // UTF-8 4 byte value
  /// let expected = Vec::from([0,1,2,3]);
  ///
  /// let value =  HeaderValue::ConnectionID([0,1,2,3]);
  /// let bytes: Vec<u8> = value.into();
  ///
  /// assert_eq!(expected, bytes);
  /// ```
  ///
  /// CreatorID
  /// ```
  /// #
  /// # use obex::object::HeaderValue;
  ///
  /// // Little Endian encoded integer value
  /// let expected = Vec::from([2, 0, 0, 0]);
  ///
  /// let value =  HeaderValue::CreatorID(2);
  /// let bytes: Vec<u8> = value.into();
  ///
  /// assert_eq!(expected, bytes);
  /// ```
  ///
  /// WANUUID
  /// ```
  /// #
  /// # use obex::object::HeaderValue;
  ///
  /// // UTF-8 4 byte value
  /// let expected = Vec::from([0,1,2,3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
  ///
  /// let value =  HeaderValue::WANUUID([0,1,2,3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
  /// let bytes: Vec<u8> = value.into();
  ///
  /// assert_eq!(expected, bytes);
  /// ```
  ///
  /// ObjectClass
  /// ```
  /// #
  /// # use obex::object::HeaderValue;
  ///
  /// // UTF-8 Byte representation of the word "test"
  /// let expected = Vec::from([0x74,0x65,0x73,0x74]);
  ///
  /// let value =  HeaderValue::ObjectClass(expected.clone());
  /// let bytes: Vec<u8> = value.into();
  ///
  /// assert_eq!(expected, bytes);
  /// ```
  ///
  /// SessionSequenceNumber
  /// ```
  /// # use obex::object::HeaderValue;
  ///
  /// // Little Endian encoded integer value
  /// let expected = Vec::from([1]);
  ///
  /// let value =  HeaderValue::SessionSequenceNumber(1);
  /// let bytes: Vec<u8> = value.into();
  ///
  /// assert_eq!(expected, bytes);
  /// ```
  ///
  /// ActionID
  /// ```
  /// # use obex::object::HeaderValue;
  ///
  /// // Little Endian encoded integer value
  /// let expected = Vec::from([1]);
  ///
  /// let value =  HeaderValue::ActionID(1);
  /// let bytes: Vec<u8> = value.into();
  ///
  /// assert_eq!(expected, bytes);
  /// ```
  ///
  /// DestName
  /// ```
  /// #
  /// # use obex::object::HeaderValue;
  ///
  /// // UTF-8 Byte representation of the word "test"
  /// let mut expected = Vec::from([0x74,0x65,0x73,0x74]);
  ///
  /// let value =  HeaderValue::DestName("test".to_string());
  /// let bytes: Vec<u8> = value.into();
  ///
  /// assert_eq!(expected, bytes);
  /// ```
  ///
  /// Permissions
  /// ```
  /// #
  /// # use obex::object::HeaderValue;
  ///
  /// // Little Endian encoded 32 bit representation of 2.
  /// let mut expected = Vec::from([2,0,0,0]);
  ///
  /// let value =  HeaderValue::Permissions(2);
  /// let bytes: Vec<u8> = value.into();
  ///
  /// assert_eq!(expected, bytes);
  /// ```
  ///
  /// SingleResponseMode
  /// ```
  /// # use obex::object::HeaderValue;
  ///
  /// // Little Endian encoded integer value
  /// let expected = Vec::from([1]);
  ///
  /// let value =  HeaderValue::SingleResponseMode(1);
  /// let bytes: Vec<u8> = value.into();
  ///
  /// assert_eq!(expected, bytes);
  /// ```
  ///
  /// SingleResponseModeParameters
  /// ```
  /// # use obex::object::HeaderValue;
  ///
  /// // Little Endian encoded integer value
  /// let expected = Vec::from([1]);
  ///
  /// let value =  HeaderValue::SingleResponseModeParameters(1);
  /// let bytes: Vec<u8> = value.into();
  ///
  /// assert_eq!(expected, bytes);
  /// ```
  fn from(value: HeaderValue) -> Vec<u8> {
    match value {
      HeaderValue::Count(val) => {
        // Convert u32 to le encoded byte array
        let value: [u8; 4] = val.to_le_bytes();
        let mut bytes: Vec<u8> = Vec::new();

        bytes.extend(value);

        return bytes;
      },
      HeaderValue::Name(val) => {
        let value: &[u8] = val.as_bytes();
        let mut bytes: Vec<u8> = Vec::new();

        bytes.extend(value);

        return bytes;
      },
      HeaderValue::Type(val) => {
        let value = val.as_bytes();
        let mut bytes: Vec<u8> = Vec::new();

        bytes.extend(value);

        return bytes;
      },
      HeaderValue::Length(val) => {
        let value = val.to_le_bytes();
        let mut bytes: Vec<u8> = Vec::new();

        bytes.extend(value);

        return bytes;
      },
      HeaderValue::Time(val) => {
        let value = val.as_bytes();
        let mut bytes: Vec<u8> = Vec::new();

        bytes.extend(value);

        return bytes;
      },
      HeaderValue::Description(val) => {
        let value = val.as_bytes();
        let mut bytes: Vec<u8> = Vec::new();

        bytes.extend(value);

        return bytes;
      },
      HeaderValue::Target(val) => {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.extend(val);

        return bytes;
      },
      HeaderValue::HTTP(val) => {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.extend(val);

        return bytes;
      },
      HeaderValue::Body(val) => {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.extend(val);

        return bytes;
      },
      HeaderValue::EndOfBody(val) => {
        let mut bytes: Vec<u8> = Vec::new();

        match val {
          Some(val) => {
            bytes.extend(val);

            return bytes;
          },
          // Note: We may want to not panic here this could have unintended side effects.
          None => {
            panic!("Cannot endoing a missing End of Body Value")
          }
        }
      },
      HeaderValue::Who(val) => {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.extend(val);

        return bytes;
      },
      HeaderValue::ConnectionID(val) => {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.extend(val);

        return bytes;
      },
      HeaderValue::ApplicationParameters() => {
        todo!("Implement application parameters");
      },
      HeaderValue::AuthenticateChallenge() => {
        todo!("Implement authenticate challenge");
      },
      HeaderValue::AuthenticateResponse() => {
        todo!("Implement authenticate response");
      },
      HeaderValue::CreatorID(val) => {
        let value = val.to_le_bytes();
        let mut bytes: Vec<u8> = Vec::new();

        bytes.extend(value);

        return bytes;
      },
      HeaderValue::WANUUID(val) => {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.extend(val);

        return bytes;
      },
      HeaderValue::ObjectClass(val) => {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.extend(val);

        return bytes;
      },
      HeaderValue::SessionParameters() => {
        todo!("Implement Session Parameters");
      },
      HeaderValue::SessionSequenceNumber(val) => {
        let value = val.to_le_bytes();
        let mut bytes: Vec<u8> = Vec::new();

        bytes.extend(value);

        return bytes;
      },
      HeaderValue::ActionID(val) => {
        let value = val.to_le_bytes();
        let mut bytes: Vec<u8> = Vec::new();

        bytes.extend(value);

        return bytes;
      },
      HeaderValue::DestName(val) => {
        let value = val.as_bytes();
        let mut bytes: Vec<u8> = Vec::new();

        bytes.extend(value);

        return bytes;
      },
      HeaderValue::Permissions(val) => {
        let value = val.to_le_bytes();
        let mut bytes: Vec<u8> = Vec::new();

        bytes.extend(value);

        return bytes;
      },
      HeaderValue::SingleResponseMode(val) => {
        let value = val.to_le_bytes();
        let mut bytes: Vec<u8> = Vec::new();

        bytes.extend(value);

        return bytes;
      },
      HeaderValue::SingleResponseModeParameters(val) => {
        let value = val.to_le_bytes();
        let mut bytes: Vec<u8> = Vec::new();

        bytes.extend(value);

        return bytes;
      }
    }
  }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum HeaderID {
  Count = 0xC0,
  Name = 0x01,
  Type = 0x42,
  Length = 0xC3,
  Time = 0x44,
  Description = 0x05,
  Target = 0x46,
  HTTP = 0x47,
  Body = 0x48,
  EndOfBody = 0x49,
  Who = 0x4A,
  ConnectionID = 0xCB,
  ApplicationParameters = 0x4C,
  AuthenticateChallenge = 0x4D,
  AuthenticateResponse = 0x4E,
  CreatorID = 0xCF,
  WANUUID = 0x50,
  ObjectClass = 0x51,
  SessionParameters = 0x52,
  SessionSequenceNumber = 0x93,
  ActionID = 0x94,
  DestName = 0x15,
  Permissions = 0xD6,
  SingleResponseMode = 0x97,
  SingleResponseModeParameters = 0x98,
}

impl From<HeaderID> for u8 {
  /// Convert a `HeaderID` to a `u8`:
  ///
  /// # Examples
  ///
  /// Count
  /// ```
  /// # use obex::object::HeaderID;
  ///
  /// let data: u8 = HeaderID::Count.into();
  ///
  /// assert_eq!(0xC0, data);
  /// ```
  fn from(id: HeaderID) -> u8 {
    match id {
      HeaderID::Count => 0xC0,
      HeaderID::Name => 0x01,
      HeaderID::Type => 0x42,
      HeaderID::Length => 0xC3,
      HeaderID::Time => 0x44,
      HeaderID::Description => 0x05,
      HeaderID::Target => 0x46,
      HeaderID::HTTP => 0x47,
      HeaderID::Body => 0x48,
      HeaderID::EndOfBody => 0x49,
      HeaderID::Who => 0x4A,
      HeaderID::ConnectionID => 0xCB,
      HeaderID::ApplicationParameters => 0x4C,
      HeaderID::AuthenticateChallenge => 0x4D,
      HeaderID::AuthenticateResponse => 0x4E,
      HeaderID::CreatorID => 0xCF,
      HeaderID::WANUUID => 0x50,
      HeaderID::ObjectClass => 0x51,
      HeaderID::SessionParameters => 0x52,
      HeaderID::SessionSequenceNumber => 0x93,
      HeaderID::ActionID => 0x94,
      HeaderID::DestName => 0x15,
      HeaderID::Permissions => 0xD6,
      HeaderID::SingleResponseMode => 0x97,
      HeaderID::SingleResponseModeParameters => 0x98,
    }
  }
}

impl TryFrom<u8> for HeaderID {
    type Error = HeaderIDError;

    /// Atttempts to convert a `u8` to a valid `HeaderID`
    ///
    /// # Examples
    /// ```
    /// # use obex::object::HeaderID;
    /// let header_id: HeaderID = HeaderID::try_from(0xC0).unwrap();
    ///
    /// assert_eq!(HeaderID::Count, header_id);
    /// ```
    fn try_from(original: u8) -> Result<Self, Self::Error> {
        match original {
          0xC0 => Ok(HeaderID::Count),
          0x01 => Ok(HeaderID::Name),
          0x42 => Ok(HeaderID::Type),
          0xC3 => Ok(HeaderID::Length),
          0x44 => Ok(HeaderID::Time),
          0x05 => Ok(HeaderID::Description),
          0x46 => Ok(HeaderID::Target),
          0x47 => Ok(HeaderID::HTTP),
          0x48 => Ok(HeaderID::Body),
          0x49 => Ok(HeaderID::EndOfBody),
          0x4A => Ok(HeaderID::Who),
          0xCB => Ok(HeaderID::ConnectionID),
          0x4C => Ok(HeaderID::ApplicationParameters),
          0x4D => Ok(HeaderID::AuthenticateChallenge),
          0x4E => Ok(HeaderID::AuthenticateResponse),
          0xCF => Ok(HeaderID::CreatorID),
          0x50 => Ok(HeaderID::WANUUID),
          0x51 => Ok(HeaderID::ObjectClass),
          0x52 => Ok(HeaderID::SessionParameters),
          0x93 => Ok(HeaderID::SessionSequenceNumber),
          0x94 => Ok(HeaderID::ActionID),
          0x15 => Ok(HeaderID::DestName),
          0xD6 => Ok(HeaderID::Permissions),
          0x97 => Ok(HeaderID::SingleResponseMode),
          0x98 => Ok(HeaderID::SingleResponseModeParameters),
          _ => Err(HeaderIDError)
        }
    }
}

impl HeaderID {
  pub fn parse(i: &[u8]) -> IResult<&[u8], HeaderID> {
    let (i, id) = le_u8(i)?;

    match HeaderID::try_from(id) {
      Ok(id) => { Ok((i, id)) },
      Err(_) => Err(nom::Err::Failure(ParseError::from_error_kind(i, nom::error::ErrorKind::Fail))),
    }
  }
}

#[derive(Debug, Clone)]
pub struct HeaderIDError;

#[derive(Debug, Clone)]
pub struct HeaderError;

pub struct TagLengthValue {
  pub tag: u8,
  pub length: u8,
  pub value: Vec<u8>, // TODO: Should be implemented as a bounded array of a fixed maximum size of 255 bytes and minimum size of 0 bytes
}