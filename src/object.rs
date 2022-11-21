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
  /// ```
  /// # use obex::object::Header;
  /// # use obex::object::HeaderID;
  /// # use obex::object::HeaderValue;
  /// let data: [u8; 5] = [0xC0, 0, 0, 0, 0];
  /// let (dat, header) = Header::parse(&data).unwrap();
  ///
  /// assert_eq!(HeaderID::Count, header.id);
  /// assert_eq!(HeaderValue::Count(0), header.value);
  /// ```
  ///
  /// ```
  /// # use obex::object::Header;
  /// # use obex::object::HeaderID;
  /// # use obex::object::HeaderValue;
  /// let data: [u8; 8] = [0x01, 5, 0, 116, 101, 120, 116, 0];
  /// let (dat, header) = Header::parse(&data).unwrap();
  ///
  /// assert_eq!(HeaderID::Name, header.id);
  /// assert_eq!(HeaderValue::Name("text\0".to_string()), header.value);
  /// ```
  ///
  /// ```
  /// # use obex::object::Header;
  /// # use obex::object::HeaderID;
  /// # use obex::object::HeaderValue;
  /// # use ascii::{AsAsciiStr, AsciiChar};
  /// let data: [u8; 7] = [0x42, 4, 0, 112, 100, 102, 0];
  /// let (dat, header) = Header::parse(&data).unwrap();
  ///
  /// assert_eq!(HeaderID::Type, header.id);
  /// assert_eq!(HeaderValue::Type("pdf\0".as_ascii_str().unwrap().to_ascii_string()), header.value);
  /// ```
  ///
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
          value: HeaderValue::Type(AsciiString::from_ascii(value).unwrap())
        };

        Ok((i, header))
      },
      HeaderID::Description => {
        let (i, length) = le_u16(i)?;
        let (i, value) = count(le_u8, length.into())(i)?;

        let header: Header = Header {
          id: id,
          value: HeaderValue::Name(String::from_utf8(value).unwrap())
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